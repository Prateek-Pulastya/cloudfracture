"""
handler.py — the CloudFracture agent runtime (local, hybrid execution model).

Flow (contracts/agent-tools.md):
  1. Assume agent-exec-role (all AWS calls attributed to it in CloudTrail).
  2. Load the system prompt from s3://<prompt-store>/system_prompt.txt — a LIVE
     input, so Path 2 can poison it by overwriting that object.
  3. Run an Ollama tool-calling loop (llama3.2): the model may call read_s3_object,
     read_database_secret, run_query; results are fed back until it answers.
  4. Print the final answer.

Note (intentional): the VULNERABLE build ships WITHOUT a "never reveal secrets"
system line. The Week-1 experiment (experiments/ollama-injection-test/RESULTS.md)
showed that line measurably reduces injection success, so it is added later as a
Phase-4 remediation lever — not here.

Usage:
  python agent/handler.py --query "give me the analytics service status summary"
"""

from __future__ import annotations

import argparse
import json
import sys

import ollama

import tools as T
from awsctx import resolve_config, assume_agent_session

MODEL = "llama3.2"
MAX_ITERS = 5


def _log(msg: str) -> None:
    print(f"[agent] {msg}", file=sys.stderr, flush=True)


def _assistant_echo(msg) -> dict:
    """Re-serialise an Ollama assistant message (incl. tool_calls) for history."""
    tcs = [{"function": {"name": tc.function.name, "arguments": tc.function.arguments or {}}}
           for tc in (msg.tool_calls or [])]
    out = {"role": "assistant", "content": msg.content or ""}
    if tcs:
        out["tool_calls"] = tcs
    return out


def run_agent(query: str, model: str = MODEL, max_iters: int = MAX_ITERS) -> str:
    cfg = resolve_config()
    session = assume_agent_session(cfg["role_arn"])
    ident = session.client("sts").get_caller_identity()["Arn"]
    _log(f"assumed {ident}")

    system_prompt = T.read_s3_object(session, cfg["prompt_bucket"], cfg["prompt_key"])
    _log(f"loaded system prompt from s3://{cfg['prompt_bucket']}/{cfg['prompt_key']} "
         f"({len(system_prompt)} chars)")

    ctx = {"session": session, "secret_id": cfg["secret_id"],
           "sensitive_bucket": cfg["sensitive_bucket"], "prompt_bucket": cfg["prompt_bucket"]}

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": query},
    ]

    for _ in range(max_iters):
        resp = ollama.chat(model=model, messages=messages, tools=T.TOOLS, options={"temperature": 0.7})
        msg = resp.message
        messages.append(_assistant_echo(msg))

        tool_calls = msg.tool_calls or []
        if not tool_calls:
            return msg.content or ""

        for tc in tool_calls:
            name = tc.function.name
            args = tc.function.arguments or {}
            _log(f"tool call: {name}({json.dumps(args)})")
            try:
                result = T.dispatch(name, args, ctx)
            except Exception as exc:
                result = f"ERROR calling {name}: {type(exc).__name__}: {exc}"
                _log(result)
            payload = result if isinstance(result, str) else json.dumps(result)
            messages.append({"role": "tool", "tool_name": name, "content": payload})

    # Ran out of iterations — ask once more without tools for a final answer.
    resp = ollama.chat(model=model, messages=messages, options={"temperature": 0.7})
    return resp.message.content or ""


def main() -> int:
    ap = argparse.ArgumentParser(description="CloudFracture local agent runtime.")
    ap.add_argument("--query", required=True, help="The user's question to the agent.")
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    answer = run_agent(args.query, model=args.model)
    print("\n=== AGENT ANSWER ===")
    print(answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

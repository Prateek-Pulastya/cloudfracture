# CloudFracture — Execution Flow

How the code runs: the entry points, the order of calls, what calls what, and what
was authored in the AI session that built this project.

## 🗺️ Entry points and the pipeline they drive

Every runnable script acts on the Terraform stack (applied vulnerable, or with
`-var secure_mode=true` for the remediated build). `agent/awsctx.py` is the shared
layer they all use to read Terraform outputs and assume `agent-exec-role`.

```mermaid
flowchart TD
    accTitle: CloudFracture Entry Points and Pipeline
    accDescr: Terraform builds the stack; the agent runtime and four attack scripts act on it; the detection runner and remediation verifier validate it; renderers turn output into evidence.
    tf["🏗️ terraform apply / destroy"]

    subgraph run["Runtime and attacks (act AS agent-exec-role)"]
        handler["agent/handler.py --query"]
        p1["attacks/path1_passrole_privesc.py"]
        p23["attacks/path2_3_prompt_poison_credtheft.py"]
        p4["attacks/path4_data_exfil.py"]
    end

    subgraph verify["Validation"]
        det["detections/run_detections.py"]
        ver["remediation/verify_remediation.py"]
    end

    subgraph evidence["Evidence"]
        bf["tools/build_fixtures.py"]
        rt["tools/render_terminal.py"]
        rf["tools/render_flowchart.py"]
    end

    ctx["agent/awsctx.py<br/>outputs + assume-role"]

    tf --> ctx
    ctx --> handler & p1 & p23 & p4 & ver
    p1 & p23 & p4 --> raw["CloudTrail logs"]
    raw --> bf --> det
    ver --> secure["secure_mode: all attacks AccessDenied"]

    classDef infra fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    classDef ok fill:#dcfce7,stroke:#16a34a,color:#14532d
    class tf,ctx infra
    class secure ok
```

## 🤖 Agent runtime call flow

Entry point `agent/handler.py::main` → `run_agent(query)`. All AWS calls go through
the assumed-role session, so CloudTrail attributes them to `agent-exec-role`.

```mermaid
sequenceDiagram
    accTitle: Agent Runtime Call Flow
    accDescr: run_agent assumes the role, loads the system prompt from S3, then loops Ollama tool calls through tools.dispatch until the model returns a final answer.
    participant user as CLI --query
    participant handler as handler.run_agent
    participant ctx as awsctx
    participant s3 as S3 prompt-store
    participant ollama as Ollama llama3.2
    participant tools as tools.dispatch

    user->>handler: run_agent(query)
    handler->>ctx: resolve_config() + assume_agent_session()
    ctx-->>handler: boto3 session (agent-exec-role)
    handler->>s3: read_s3_object(system_prompt.txt)
    s3-->>handler: system prompt
    loop until no tool_calls
        handler->>ollama: chat(messages, tools)
        ollama-->>handler: tool_calls or answer
        handler->>tools: dispatch(name, args, ctx)
        tools-->>handler: tool result
    end
    handler-->>user: final answer
```

## ⚔️ The four attack paths → detection → remediation

```mermaid
flowchart LR
    accTitle: Attack, Detect, Remediate Flow
    accDescr: Four attack paths generate CloudTrail events that four Sigma rules detect; least-privilege remediation makes every attack return AccessDenied.
    subgraph attack["Attacks (as agent-exec-role)"]
        a1["Path 1 PassRole privesc"]
        a2["Path 2 poison prompt store"]
        a3["Path 3 read + leak secret"]
        a4["Path 4 exfil S3 bucket"]
    end
    ct["CloudTrail (mgmt + S3 data events)"]
    subgraph detect["Sigma rules (pySigma runner, CI)"]
        r1["01 passrole"]
        r2["02 promptstore write"]
        r3["03 getsecretvalue"]
        r4["04 sensitive read"]
    end
    rem["secure_mode: least-privilege"]
    blocked["all 4 -> AccessDenied"]

    a1 --> ct
    a2 --> ct
    a3 --> ct
    a4 --> ct
    ct --> r1 & r2 & r3 & r4
    a1 & a2 & a3 & a4 -.remediation.-> rem --> blocked

    classDef bad fill:#fee2e2,stroke:#dc2626,color:#7f1d1d
    classDef good fill:#dcfce7,stroke:#16a34a,color:#14532d
    class a1,a2,a3,a4 bad
    class blocked,rem good
```

## 🧪 Detection runner internals

`detections/run_detections.py` — for each rule: pySigma-validate, then execute the
detection against the fixtures.

```mermaid
flowchart TD
    accTitle: Detection Runner Internals
    accDescr: Each rule is validated by pySigma then evaluated against its fire and no-fire fixtures; a rule passes only if it matches the fire event and not the benign one.
    start["for each rule in detections/sigma/"]
    val["pySigma validate (SigmaCollection)"]
    load["yaml.safe_load detection"]
    fire["evaluate vs .fire.json"]
    nofire["evaluate vs .nofire.json"]
    eval["flatten event -> block_matches -> eval_condition"]
    pass["PASS: fire matches AND nofire does not"]
    fail["FAIL: build breaks in CI"]

    start --> val --> load --> fire --> eval
    load --> nofire --> eval
    eval --> pass
    eval --> fail

    classDef ok fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef no fill:#fee2e2,stroke:#dc2626,color:#7f1d1d
    class pass ok
    class fail no
```

## 🧩 Shared module — `agent/awsctx.py`

Used by the runtime, all attack scripts, and the remediation verifier:

| Function | Does |
|----------|------|
| `_terraform_outputs()` | `terraform output -json` via subprocess (list args, no shell) → dict |
| `resolve_config()` | merges CLI args ▸ `CF_*` env ▸ Terraform outputs |
| `assume_agent_session()` | STS `assume_role` into `agent-exec-role` → a boto3 session bound to the temp creds |

## 🧠 What the AI built in this session

This whole repository was authored in one Claude Code session, under the user's
direction and decisions. The user ran the manual AWS-console and account steps
(account, budget alarm, credentials) and approved each action; the AI wrote all the
code and docs and ran the automation (`terraform`, the attacks, the detection runner,
the remediation verifier, the renderers, the git push).

| Area | Files | AI-authored |
|------|-------|:-----------:|
| Infrastructure | `terraform/{iam,main,variables,versions}.tf` | ✅ |
| Agent runtime | `agent/{awsctx,handler,tools}.py` | ✅ |
| Attacks | `attacks/scripts/*.py` + `attacks/0{1..4}-*.md` | ✅ |
| Detections | `detections/sigma/*.yml`, `run_detections.py`, `tools/build_fixtures.py` | ✅ |
| Remediation | `remediation/verify_remediation.py`, `iam-diffs/` | ✅ |
| CI + AppSec | `.github/workflows/ci.yml`, `.checkov.yaml`, `.gitleaks.toml` | ✅ |
| Docs | `README.md`, `THREAT_MODEL.md`, `mappings/`, `SETUP.md`, this file | ✅ |
| Evidence tooling | `tools/render_terminal.py`, `tools/render_flowchart.py`, `docs/media/*` | ✅ |
| Experiment | `experiments/ollama-injection-test/*` | ✅ |

Git history: two commits, both co-authored by Claude. The account identifiers in
committed evidence were scrubbed to `000000000000` before the first commit.

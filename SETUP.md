# CloudFracture — Complete Setup Guide (plain-English)

Everything you install, every account you make, in the exact order, with a
copy-paste command and a "check it worked" step for each. Written for someone who
is **not** a cloud expert. Follow top to bottom. You do **not** need to finish it
all today — see "Do this in stages".

> **Windows note:** every command below goes in **PowerShell**. Open it: press
> **Start**, type **PowerShell**, press **Enter**. Paste with **Ctrl+V**, run with
> **Enter**. After installing anything, **close and re-open PowerShell** before you
> check it — new tools only appear in a fresh window.

---

## 0) The rules that keep you safe (read once)

This project uses **real AWS** (a card is attached). Done right it costs **under
€10 total**. Five rules:

1. **Use a brand-new, dedicated AWS account** for this and nothing else.
2. **Set a €10 spending alarm BEFORE you build anything.**
3. **Turn on MFA** (phone login codes) on the master login.
4. **Tear everything down after every session** — `terraform destroy`. Skipping it
   once is the #1 cause of surprise bills.
5. **Secret keys are passwords.** Never paste them into the AI chat or any project
   file. They go in one place: `aws configure`, which **you** run.

**What I (Claude) can't do:** create your AWS/GitHub accounts, enter your card,
type passwords, or type your secret keys — security rules forbid it. **What I
can do:** install tools, write all the code, and once you've run `aws configure`,
run the AWS/Terraform commands for you.

---

## Do this in stages (don't overwhelm yourself)

| Stage | What | Cost / risk | When |
|---|---|---|---|
| **1** | Local tools + run the first experiment | Free, no card, no risk | **Today** |
| **2** | AWS account + AWS toolchain | < €10, careful | When ready to build the cloud |
| **3** | Attack + scanner tools | Free | Later, at the phase that needs them |
| **4** | GitHub account (publish + CI) | Free, no card | Near the end |

Already installed on your PC: **Python 3.10**, **Git**, **winget**, **uv**. ✅

---

# STAGE 1 — Local setup (free, today)

The AI agent in this project runs **on your PC** (local model = zero cost), so
these local tools matter even for the cloud part later.

### 1.1 — Install Ollama (the local AI)
```powershell
winget install Ollama.Ollama
```
Close and re-open PowerShell, then download the model (~2 GB):
```powershell
ollama pull llama3.2
```
Check:
```powershell
ollama --version
ollama list
```
You should see a version and `llama3.2` listed.

### 1.2 — Set up an isolated Python space for the project
This keeps the project's Python bits from clashing with anything else on your PC.
```powershell
python -m venv "E:\Learning\Projects\Cloud Security\cloudfracture\.venv"
```
Turn it on (do this each time you work on Python here):
```powershell
& "E:\Learning\Projects\Cloud Security\cloudfracture\.venv\Scripts\Activate.ps1"
```
Your prompt now shows `(.venv)`. Install the project's Python needs:
```powershell
pip install ollama boto3
```
(`ollama` = talk to the local model; `boto3` = talk to AWS from Python.)

### 1.3 — Tell Git who you are (once)
```powershell
git config --global user.name "Your Name"
```
```powershell
git config --global user.email "you@example.com"
```

**Stage 1 done.** Tell me, and I'll run the Ollama injection experiment — the
Week-1 test that proves the AI attack is viable before you spend on AWS.

---

# STAGE 2 — AWS account (the careful part)

Do this when you're ready to build the cloud workload.

### 2.1 — Create a fresh AWS account  *(you do this — I can't)*
1. Go to **https://aws.amazon.com** → **Create an AWS Account**.
2. Email, strong password, account name (e.g. `cloudfracture-lab`).
3. Contact details.
4. **Credit/debit card.** AWS may place a ~€1 temporary hold that is refunded —
   normal.
5. **Verify your phone** (they send a code).
6. Choose **Basic support — Free**.

### 2.2 — Lock the master (root) login *(immediately)*
Your email+password is the **root user** — the master key. Protect it, then stop
using it day-to-day.
1. Sign in at **https://console.aws.amazon.com**.
2. Top-right → your name → **Security credentials**.
3. **Multi-factor authentication (MFA)** → **Assign MFA device**.
4. On your **phone**, install an authenticator app (Google Authenticator /
   Microsoft Authenticator / Authy — free). Choose **Authenticator app**, scan the
   QR code, enter the two codes. Done.

### 2.3 — Set the €10 spending alarm *(BEFORE building anything)*
1. Console search → **Billing** → **Billing and Cost Management**.
2. **Budgets** → **Create budget** → **Use a template** → **Monthly cost budget**
   (or "Zero spend").
3. Amount **10**. Alerts at **80%** and **100%**. Recipient = **your email**.
4. Create. Also: **Billing preferences** → turn on **Free Tier usage alerts**.

### 2.4 — Make a limited "tool" user *(don't use root for work)*
1. Console search → **IAM** → **Users** → **Create user**.
2. Name `cloudfracture-cli`. Leave console access **off**. Next.
3. **Attach policies directly** → tick **AdministratorAccess** (Terraform needs to
   create IAM roles). Next → **Create user**.

> Broad rights are OK **only** because this is a throwaway lab account with a €10
> cap. Never do this in a real/shared account.

### 2.5 — Create its access keys
1. Open the `cloudfracture-cli` user → **Security credentials** tab.
2. **Access keys** → **Create access key** → **Command Line Interface (CLI)** →
   tick the box → **Create**.
3. **Download the .csv** (the secret is shown once). Keep it safe on your PC —
   **not** inside the project folder.

> 🔐 Do **not** paste these keys into the AI chat or any file. Next step only.

### 2.6 — Install the AWS CLI
```powershell
winget install Amazon.AWSCLI
```
Close/re-open PowerShell, then:
```powershell
aws --version
```

### 2.7 — Connect the CLI to your account  *(type this in YOUR OWN PowerShell)*
Do **not** run this through the AI chat — it asks for your secret key.
```powershell
aws configure
```
Answer:
- **AWS Access Key ID** → paste from the .csv
- **AWS Secret Access Key** → paste from the .csv
- **Default region name** → `eu-central-1`
- **Default output format** → `json`

Check it linked (shows your account number, no secrets):
```powershell
aws sts get-caller-identity
```
Seeing your account ID + the `cloudfracture-cli` user = connected.

### 2.8 — Install Terraform
```powershell
winget install Hashicorp.Terraform
```
Close/re-open PowerShell, then:
```powershell
terraform --version
```

**Stage 2 done.** Tell me — I can then build (`terraform apply`) and tear down
(`terraform destroy`) the lab for you.

---

# STAGE 3 — Attack + scanner tools (later, per phase)

**You do NOT need these yet.** We install each at the start of the phase that uses
it. Listed here so the picture is complete.

### 3a — Clean Python tools (install when Phase 2 starts)
Best installed **isolated** with `pipx` so they never clash:
```powershell
python -m pip install --user pipx
```
```powershell
python -m pipx ensurepath
```
Close/re-open PowerShell, then, when Phase 2 begins:
```powershell
pipx install pacu
```
```powershell
pipx install principalmapper
```
```powershell
pipx install cloudsplaining
```
(`pacu` = AWS exploitation; `principalmapper`/PMapper = visualize the privesc
path; `cloudsplaining` = flag the over-permissions.)

### 3b — CI-first tools (run in GitHub Actions, not locally)
Semgrep, Gitleaks, Syft, Checkov/tfsec, Stratus Red Team are **fiddly on native
Windows** and are meant to run in the **CI pipeline** (Stage 4) anyway. Don't fight
them locally in week 1. When we build the pipeline in Phase 4, they run in the
cloud on every push — no Windows install needed. If you ever want one locally,
we'll set it up together for that phase.

The detection tooling (**sigma-cli**, **pySigma**) installs cleanly when Phase 3
starts:
```powershell
pipx install sigma-cli
```

---

# STAGE 4 — GitHub (publish + CI, near the end)

Free, **no card**. Needed to publish the repo and run the automated security
pipeline.
1. Go to **https://github.com** → **Sign up**. Pick a professional username
   (recruiters see it).
2. Turn on **2FA** (Settings → Password and authentication) — same idea as AWS MFA.
3. Optional but handy — the GitHub CLI, so I can help with repo/PR tasks:
   ```powershell
   winget install GitHub.cli
   ```
   Then you authenticate it yourself:
   ```powershell
   gh auth login
   ```

---

# Final "everything works" check

Open a fresh PowerShell and run these. Every line should print a version, not an
error. (Stage-3 tools only after you've installed them.)
```powershell
python --version; git --version; ollama --version; aws --version; terraform --version
```

---

# The one habit that keeps you safe

At the end of **every** AWS session, from the `terraform/` folder:
```powershell
terraform destroy -auto-approve
```
It deletes everything the project created, so nothing keeps billing. I'll always
remind you — build the reflex.

---

## Accounts summary

| Account | Cost | Card? | 2FA/MFA | When |
|---|---|---|---|---|
| **AWS** | < €10 total | Yes | Yes (2.2) | Stage 2 |
| **Ollama** | Free | No account | — | Stage 1 |
| **GitHub** | Free | No | Yes (Stage 4) | Stage 4 |

No paid AI APIs — the model runs locally via Ollama.

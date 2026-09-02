# SBOM — Software Bill of Materials

A CycloneDX SBOM is generated in CI by **Syft** (`sbom-syft` job in
`.github/workflows/ci.yml`) and published as the `cloudfracture-sbom` build
artifact (`sbom/cloudfracture.cdx.json`).

## Why
Supply-chain transparency — a named requirement in the AppSec job ads. The SBOM
enumerates every dependency (Python packages, GitHub Actions, etc.) so a consumer
can check them against vulnerability feeds.

## Generate locally
```bash
# https://github.com/anchore/syft
syft dir:. -o cyclonedx-json=sbom/cloudfracture.cdx.json
```
Syft is Linux/macOS-first; on Windows use WSL, Docker, or let CI produce it. The
committed SBOM (if present) is a snapshot; CI regenerates it on every push.

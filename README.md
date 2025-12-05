# Detect-Secrets → SARIF Converter Action

Convert `detect-secrets` JSON output into SARIF 2.1.0 so you can upload secret-detection findings to GitHub Advanced Security (Code Scanning) with a single composite GitHub Action.

## Why this exists

`detect-secrets` does not emit SARIF on its own, but SARIF is the format Code Scanning requires. This action bridges the gap by:

- Reading any detect-secrets JSON file (baseline or scan output) from your workspace.
- Translating each finding into a SARIF `rule`/`result` pair with `tool.driver.name = detect-secrets`.
- Emitting the SARIF file path and number of findings as reusable workflow outputs.

The converter only uses the Python standard library and never prints the raw secret value (hashed secrets are preserved when available).

## Requirements

- GitHub-hosted or self-hosted runners with Python 3 (the action installs it via `actions/setup-python`).
- A detect-secrets JSON file generated earlier in the workflow (for example via `detect-secrets scan` or by checking in a baseline file).

## Quick start

```yaml
name: Security scan
on:
  push:
    branches: [main]

jobs:
  detect-secrets:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run detect-secrets scan
        run: |
          pip install detect-secrets
          detect-secrets scan > detect_secrets_results.json

      - id: convert
        name: Convert detect-secrets JSON to SARIF
        uses: ry-bar/detect-secrets-sarif-action@main
        with:
          input-file: detect_secrets_results.json
          output-file: results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ${{ steps.convert.outputs['sarif-file'] }}
```

> Tip: when using the action from another repository you should pin `ry-bar/detect-secrets-sarif-action` to a release tag or commit SHA instead of `@main`.

## Inputs

| Input | Required | Default | Description |
| ----- | -------- | ------- | ----------- |
| `input-file` | Yes | `detect_secrets_baseline.json` | Path (relative to the workspace) to the detect-secrets JSON file you want to convert. |
| `output-file` | Yes | `results.sarif` | Path to the SARIF file that will be written. Directories are created if needed. |

## Outputs

| Output | Description |
| ------ | ----------- |
| `sarif-file` | Path (relative to the workspace) of the SARIF document that was generated. |
| `findings-count` | Total number of detect-secrets findings that were converted into the SARIF results array. |

## Local development

You can exercise the converter script without running a workflow:

```bash
python3 converter.py --input examples/sample-input.json --output /tmp/out.sarif
cat /tmp/out.sarif
```

The script prints two `key=value` lines (`sarif_file=...` and `findings_count=...`), which is how the composite action captures its outputs.

## Repository layout

- `action.yml` – composite action definition used by workflows.
- `converter.py` – Python script that transforms detect-secrets JSON into SARIF 2.1.0.
- `detect_secrets_baseline.json` – example baseline you can use for demo runs.
- `examples/` – sample input and output pairs.
- `.github/workflows/security-scan.yml` – reference workflow showing the action in use.

## Troubleshooting

- The upload step must use a published version of `github/codeql-action/upload-sarif` (currently `v2`). Using a non-existent tag such as `v4` will cause the workflow to fail before the SARIF file is uploaded.
- If the converter cannot find or parse the input JSON file it still emits a valid SARIF document with zero results; double-check the `input-file` path and that your detect-secrets step actually produced output.

## License

MIT — see `LICENSE`.

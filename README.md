# Detect-Secrets → SARIF Converter GitHub Action

This repository contains a small GitHub Action that converts the JSON output of the open-source tool `detect-secrets` into SARIF 2.1.0 format so it can be uploaded to GitHub Advanced Security Code Scanning.

## What it does

- Reads a `detect-secrets` JSON output file (for example, a baseline or a scan output).
- Converts findings into a SARIF 2.1.0 file with `tool.driver.name` set to `detect-secrets`.
- Each detect-secrets finding becomes a SARIF `result` with `level: warning`.
- Unique detector types are emitted as SARIF `rules`.

The converter intentionally avoids exposing raw secrets (it preserves hashed_secret when present but does not include secret values).

## Files in this repository

- `action.yml` — the composite GitHub Action manifest.
- `converter.py` — converter script (pure Python stdlib).
- `examples/sample-input.json` — sample detect-secrets JSON input (from `detect_secrets_baseline.json`).
- `examples/sample-output.sarif` — example SARIF output produced from the sample input.
- `.github/workflows/security-scan.yml` — example workflow that uses this action and uploads SARIF to Code Scanning.
- `LICENSE` — MIT license.
- `uv.lock` — (stub for dependency lock; intentionally minimal).

## Inputs & Outputs

Inputs (action inputs):

- `input-file` (required): path to the detect-secrets JSON input (default: `detect_secrets_baseline.json`).
- `output-file` (required): path to write the SARIF file (default: `results.sarif`).

Outputs (action outputs):

- `sarif-file`: path to the generated SARIF file.
- `findings-count`: number of findings converted.

## Example usage (workflow)

Place this file in `.github/workflows/security-scan.yml` in the repo you want to test (an example is provided in this repo):

```yaml
name: Security scan
on:
  push:
    branches: [ main ]

jobs:
  convert-and-upload:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - id: convert
        name: Run detect-secrets → SARIF converter
        uses: ./
        with:
          input-file: detect_secrets_baseline.json
          output-file: results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ${{ steps.convert.outputs.sarif-file }}
```

> Note: In a real scan you would run `detect-secrets scan` or `detect-secrets audit` to generate the JSON input first. The example here uses the baseline file included for demonstration.

## Example SARIF (snippet)

Below is a small excerpt of what the SARIF looks like (full example is in `examples/sample-output.sarif`):

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "detect-secrets" } },
      "results": [
        {
          "ruleId": "AWS_Access_Key",
          "level": "warning",
          "message": { "text": "AWS Access Key found in .env" },
          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": ".env" }, "region": { "startLine": 2 } } } ]
        }
      ]
    }
  ]
}
```

## Development

The converter is written to use only the Python standard library to keep the action lightweight. You can run it locally:

```bash
python3 converter.py --input examples/sample-input.json --output /tmp/out.sarif
```

It will print two lines on success:

- `sarif_file=/tmp/out.sarif`
- `findings_count=3`

## License

MIT — see `LICENSE`.

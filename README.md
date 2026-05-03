# WebScrapeHelper — Bitcoin ECDSA Signature Analyzer

A Flask-based research tool for inspecting Bitcoin transactions for textbook
ECDSA weaknesses (low-S, repeated `r`/nonce reuse) and, when given real per-input
message hashes, applying the standard nonce-reuse recovery formula
`x = (s·k − z) / r mod n`.

## Status & honest caveats

* The transaction analyzer fetches `r` and `s` from the input scriptSigs via
  `blockchain.info` and detects shared `r` across inputs.
* The analyzer does **not** reconstruct the real per-input Bitcoin
  SIGHASH_ALL preimage. Recovering a private key from the pure
  transaction-id endpoint therefore intentionally stops after detection — the
  required ECDSA `z` values aren't available.
* Use the `POST /api/analyze/ecdsa`, `POST /api/recover/low-s-with-nonce`,
  `POST /api/calculate/nonce` or the offline calculator at
  `/standalone-calculator` when you have real `z` values to feed in.

This tool is for defensive security research / education. It is **not** a
"key recovery" magic wand — the math only works when the underlying
mathematical preconditions are actually satisfied by the data you supply.

## Routes

| Path | Purpose |
| --- | --- |
| `/` | Landing page with quick links and live-scan buttons |
| `/transaction` | Analyze a single transaction by id |
| `/address` | Analyze every transaction for a given address |
| `/ecdsa-analysis` | Manual ECDSA parameter playground |
| `/standalone-calculator` | Render the offline ECDSA calculator |
| `/download-calculator` | Download the offline calculator HTML |
| `/api/analyze/transaction` | `POST {tx_id}` |
| `/api/analyze/address` | `POST {address}` |
| `/api/analyze/ecdsa` | `POST {tx_id}` or `POST {r1, s1, m1, r2, s2, m2}` |
| `/api/recover/low-s-with-nonce` | `POST {r, s, z, k}` |
| `/api/recover/malleability-signatures` | `POST {r, s_values, z}` |
| `/api/calculate/nonce` | `POST {r, s1, s2, z1, z2}` |
| `/api/calculate/nonce-from-private-key` | `POST {r, s, z, x}` |
| `/api/auto-scan` | Scan the latest block for vulnerable signatures |
| `/api/monitor-mempool` | Scan the mempool for vulnerable signatures |

## Local setup

```bash
# Option A: pip
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Option B: uv (uses pyproject.toml)
uv sync

# Run the dev server
FLASK_DEBUG=1 python main.py
# or
gunicorn -w 2 -b 0.0.0.0:5000 main:app
```

The server listens on port `5000` by default. `FLASK_DEBUG` and `PORT` env
vars are honored by `main.py`.

## Project layout

```
app.py                       Flask routes
btc_analyzer.py              ECDSA analysis / recovery code
attached_assets/             utils, validators, address list
static/                      JS, CSS, downloadable offline calculator
*.html                       Jinja templates (template_folder='.')
block_scanner.py             Standalone block scanner
continuous_scanner.py        Long-running mempool / block hunter
enhanced_hunter.py           Async variant of the hunter
run_hunter.py                CLI entry point for the hunters
```

## Security & ethics

This is a defensive analysis tool. Do **not** use it to attempt access to
Bitcoin funds you do not control. The recovery code only succeeds against
mathematical preconditions that arise from genuinely broken signing
implementations; keys returned for transactions whose preconditions are not
met are not valid keys.

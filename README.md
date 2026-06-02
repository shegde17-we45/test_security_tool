# test_security_tool

Security demo repo for **Apiiro** (native scanning only — no Semgrep required).

## Contents

| Path | Purpose |
|------|---------|
| `juice-shop/` | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — large vulnerable Node/Angular app for Apiiro SAST/SCA/API findings |
| `app.py`, `example_sast.py`, `vulnerable_sample.py` | Small Python/Flask samples (optional; fewer findings than Juice Shop) |
| `docs/APIRO_SETUP.md` | Step-by-step Apiiro connection after push |

## Quick start (Apiiro)

1. Push this repo to GitHub (`main`).
2. In Apiiro, link **`shegde17-we45/test_security_tool`** and select **all `juice-shop` modules**.
3. Wait for the first scan to finish, then review **Risks**.

See [docs/APIRO_SETUP.md](docs/APIRO_SETUP.md) for troubleshooting.

## Local Juice Shop (optional)

```bash
cd juice-shop
npm install   # first time only
npm start
```

Default URL: http://localhost:3000 (do not expose to the public internet).

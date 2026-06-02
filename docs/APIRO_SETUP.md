# Apiiro + OWASP Juice Shop (Apiiro-only, no Semgrep)

This repo includes a **shallow copy** of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) under `juice-shop/` so Apiiro can run **native SAST, SCA, secrets, and API/code analysis** on a large, intentionally vulnerable Node.js application.

## After you push to GitHub

1. In **Apiiro**, open your application (or create **Security Review** → new application).
2. **Repository**: `shegde17-we45/test_security_tool` (branch `main`).
3. **Module selection**: select **all modules**, especially anything under **`juice-shop`** (Node/Express backend, Angular frontend). You can include or skip the small Python samples at the repo root.
4. Save and wait **30–90 minutes** for the first full scan on Juice Shop (large codebase).
5. In Apiiro, open **Risks / Findings** (and **APIs** / inventory if enabled). Expect **many** SCA + SAST items once scanning completes.

## What should populate (Apiiro-only)

| Signal | Source in this repo |
|--------|---------------------|
| SAST | Injection, XSS, unsafe patterns in `juice-shop/` TypeScript/JavaScript |
| SCA | Dependencies in `juice-shop/package.json` |
| Secrets | Hardcoded keys and sample secrets in Juice Shop |
| APIs / DCA | REST routes and application structure in `juice-shop/` |

You do **not** need Semgrep or `.github/workflows/semgrep.yml` for this demo.

## If risks stay at 0

Ask your Apiiro admin to confirm for this application:

- Native **SAST** and **SCA** are enabled (not inventory-only).
- The repo finished **indexing** on `main` after the Juice Shop push.
- No policies exclude `juice-shop/` paths or filter all severities.

## Updating Juice Shop later

```bash
cd juice-shop
git init  # only if refreshing from upstream
git remote add upstream https://github.com/juice-shop/juice-shop.git
git fetch --depth 1 upstream master
git checkout FETCH_HEAD -- .
rm -rf .git
```

Or re-run from repo root:

```bash
rm -rf juice-shop
git clone --depth 1 --branch master https://github.com/juice-shop/juice-shop.git juice-shop
rm -rf juice-shop/.git
```

Then commit and push.

## Dedicated Juice Shop repo (optional)

For a cleaner Apiiro app that only contains Juice Shop, fork [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) on GitHub and point Apiiro at that repo instead of this monorepo.

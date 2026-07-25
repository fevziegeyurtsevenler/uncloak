# Publishing uncloak to PyPI

uncloak ships a GitHub Actions workflow (`.github/workflows/publish.yml`) that
publishes to PyPI using **Trusted Publishing** (OIDC) — no API token is stored in
the repo.

## One-time setup

1. Create the `uncloak` project on [PyPI](https://pypi.org) (or reserve the name
   with a first manual upload).
2. On PyPI → *Your projects* → `uncloak` → *Publishing* → **Add a pending publisher**:
   - Owner: `fevziegeyurtsevenler`
   - Repository: `uncloak`
   - Workflow name: `publish.yml`
   - Environment: `pypi`
3. In this repo → *Settings → Secrets and variables → Actions → Variables* → add
   `PYPI_READY = true` (this gates the publish job so it never fails before setup).
4. Create a GitHub Release (or run the `publish` workflow manually). The workflow
   builds the wheel/sdist and publishes to PyPI.

After that, `pip install uncloak` works, and each new Release publishes automatically.

## Manual fallback

```bash
python -m pip install build twine
python -m build
python -m twine upload dist/*
```

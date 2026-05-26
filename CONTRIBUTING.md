# Contributing

Thanks for your interest in improving the MICCMAC Zero Trust Device Readiness Toolkit.

## Ways to contribute

- **Implement checks.** Each module in `miccmac/checks/` contains scaffolded
  checks marked `NOT_IMPLEMENTED`. Real detection logic for any platform
  (Windows, Linux, macOS, cloud) is welcome.
- **Add platform collectors.** Helpers that gather device facts and pass them
  to checks via the `context` dict.
- **Improve control mappings.** See `data/control-mappings.yaml`.
- **Report issues.** Bugs, false results, and methodology questions are all useful.

## Development setup

```bash
git clone https://github.com/liliyke/miccmac-zt-readiness.git
cd miccmac-zt-readiness
python -m pip install -r requirements-dev.txt
python -m miccmac assess localhost
```

## Pull requests

1. Open an issue describing the change before large work.
2. Keep one logical change per pull request.
3. Each new check should set `status`, `detail`, `evidence`, and `control_refs`.
4. Run `pytest` before submitting.

## Conduct

This project follows the contributor expectations in `CODE_OF_CONDUCT.md`.
Be respectful and constructive.

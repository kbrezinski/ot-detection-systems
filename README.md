# provenance-detection-systems

[![CI](https://github.com/kbrezinski/ot-detection-systems/actions/workflows/ci.yml/badge.svg)](https://github.com/kbrezinski/ot-detection-systems/actions/workflows/ci.yml)

An early-stage PyTorch project for provenance detection. The importable package is `provdetect`.

> **Status:** under active development. The project goals, methods and results will be documented here as they take shape. So far the repository contains the reproducible-runtime scaffolding that later work builds on.

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/) for environment and dependency management

Runtime dependencies are `numpy` and `torch`. `uv.lock` pins exact versions.

## Getting started

```bash
git clone https://github.com/kbrezinski/ot-detection-systems.git
cd ot-detection-systems
uv sync --group dev
```

Run the tests to check the setup:

```bash
uv run pytest
```

## Reproducibility

Deterministic behaviour is a design goal. `provdetect.config` provides:

- `RuntimeConfig`, a frozen dataclass holding the seed, device and determinism/cuDNN settings.
- `apply_runtime_config(config)`, which seeds Python, NumPy and PyTorch, applies the cuDNN settings, and returns the config with `device="auto"` resolved to `"cuda"` or `"cpu"`.

```python
from provdetect.config import RuntimeConfig, apply_runtime_config

config = apply_runtime_config(RuntimeConfig(seed=1337, device="auto"))
print(config.device)  # "cuda" if available, otherwise "cpu"
```

Deterministic mode calls `torch.use_deterministic_algorithms(True)`, so a PyTorch operation without a deterministic implementation raises an error instead of silently running non-deterministically. For CUDA runs, set `CUBLAS_WORKSPACE_CONFIG=:4096:8` in the environment before PyTorch starts, as `tests/conftest.py` does.

## Project layout

```text
src/provdetect/     Package source (config, paths, core)
tests/              Pytest suite
main.py             Placeholder entry point
```

`provdetect.paths` defines the locations used for data (`data/`), models (`models/`) and run artifacts (`artifacts/`) at the repository root. `ensure_directories()` creates them. These directories are git-ignored.

## Development

```bash
uv run pytest                 # run the tests
uv run ruff check . --fix     # lint
uv run ruff format .          # format
uv run codespell .            # spell check
pre-commit install            # run the checks automatically on commit
```

GitHub Actions runs lint, format check, tests, a package build and an import smoke test on Linux, Windows and macOS. Spelling and link checks run in their own workflows.

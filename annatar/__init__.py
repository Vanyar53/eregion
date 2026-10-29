def _version() -> str:
    """The package's version, from its one source: pyproject.toml (REL1, `make release`). The
    tree's file first, in a checkout or an editable install — the installed metadata is frozen at
    install time (an editable install made at 0.3.0 still says 0.3.0) —, else the installed
    package's metadata (a wheel), else « 0+unknown »."""
    import re
    from pathlib import Path
    try:
        text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        if re.search(r'(?m)^name = "eregion"$', text) and (m := re.search(r'(?m)^version = "([^"]+)"$', text)):
            return m.group(1)
    except OSError:
        pass
    try:
        from importlib.metadata import version
        return version("eregion")
    except Exception:   # PackageNotFoundError: an uninstalled tree without its pyproject.toml
        return "0+unknown"


__version__ = _version()

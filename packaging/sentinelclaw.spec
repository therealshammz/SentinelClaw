# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for standalone SentinelClaw binaries (P6-29).

Build a self-contained one-file console executable per OS:

    python -m PyInstaller --noconfirm packaging/sentinelclaw.spec

Artifacts:

    dist/sentinelclaw        Linux / macOS
    dist/sentinelclaw.exe    Windows

What this spec bundles:

* every Python module the ``sentinelclaw`` package imports
  (entry script: ``sentinelclaw/__main__.py``);
* the packaged detection-rule trees under ``sentinelclaw/rules/``
  (``*.yaml``, the converted ``sigma/*.yaml`` rules, and the optional
  ``yara/*`` rules) as data files, so the frozen ``rules`` / scan /
  file-analysis commands resolve them at the bundled
  ``sentinelclaw/rules`` location at runtime;
* ``win32evtlog`` as a hidden import: the Windows event collector
  imports it lazily inside a function
  (``sentinelclaw/tools/windows_event_analyzer.py``), so static
  analysis alone does not guarantee it is collected on Windows.

Optional extras (pcap/Scapy, python-evtx, yara-python) are NOT bundled
unconditionally. They are only collected when they are importable in
the build environment, matching how SentinelClaw treats them at
runtime: optional collectors degrade gracefully when their library is
missing. Install the extra before building to include it, e.g.
``python -m pip install ".[build,pcap,evtx,yara]"``.

Note on paths: data sources below are relative to this spec file
(PyInstaller resolves relative spec paths against the spec directory).
"""

PROJECT_ROOT = SPECPATH + "/.."  # noqa: F821 (SPECPATH injected by PyInstaller)

datas = [
    (PROJECT_ROOT + "/sentinelclaw/rules/*.yaml", "sentinelclaw/rules"),
    (PROJECT_ROOT + "/sentinelclaw/rules/sigma/*.yaml", "sentinelclaw/rules/sigma"),
    (PROJECT_ROOT + "/sentinelclaw/rules/yara/*", "sentinelclaw/rules/yara"),
]

hiddenimports = [
    # Windows-only lazy import (safe on other platforms: pywin32 is not
    # installed there, so nothing is collected and the module is absent
    # at runtime, which the collector handles gracefully).
    "win32evtlog",
]

a = Analysis(
    [PROJECT_ROOT + "/sentinelclaw/__main__.py"],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="sentinelclaw",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

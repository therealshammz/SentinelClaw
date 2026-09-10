# SentinelClaw packaging (P6-29)

Standalone, OS-native binaries are produced with **PyInstaller** from
the spec file in this directory. PyInstaller is a build-time-only
dependency (the `[build]` extra in `pyproject.toml`); SentinelClaw
itself never imports it at runtime.

## Building

Install the build tooling once:

```bash
python -m pip install -e ".[build]"
```

Build for the current operating system:

```bash
# Linux / macOS
scripts/build_binary.sh

# Windows (PowerShell)
.\scripts\build_binary.ps1
```

or invoke PyInstaller directly:

```bash
python -m PyInstaller --noconfirm packaging/sentinelclaw.spec
```

Artifacts:

```text
dist/sentinelclaw        Linux / macOS executable
dist/sentinelclaw.exe    Windows executable
```

Both build scripts are thin wrappers: they install `.[build]` and run
PyInstaller against `packaging/sentinelclaw.spec`. A local Windows
build requires a Windows machine; the CI `build` job (see
`.github/workflows/ci.yml`) builds on `ubuntu-latest` and
`windows-latest` on every push and uploads the binaries as GitHub
Actions artifacts, which is the supported way to obtain the Windows
binary from a Linux development workflow.

### What the spec bundles

* The full `sentinelclaw` Python package (entry script:
  `sentinelclaw/__main__.py`).
* The packaged detection-rule trees as data files --
  `sentinelclaw/rules/*.yaml`, `sentinelclaw/rules/sigma/*.yaml`, and
  `sentinelclaw/rules/yara/*` -- so the frozen `rules`, `scan`, and
  `file` commands resolve rules at their bundled location.
* `win32evtlog` (Windows) as a hidden import: the event-log collector
  imports it lazily inside a function.

### Optional runtime extras

Scapy (`pcap`), `python-evtx` (`evtx`), and `yara-python` (`yara`) are
optional. They are only bundled when they are importable in the build
environment. To produce a binary that includes them:

```bash
python -m pip install -e ".[build,pcap,evtx,yara]"
python -m PyInstaller --noconfirm packaging/sentinelclaw.spec
```

Without them the corresponding collectors degrade gracefully at
runtime (the same behavior as a source install without extras).

## Smoke test

After building, run the equivalent of the CI smoke test:

```bash
dist/sentinelclaw --help
dist/sentinelclaw rules          # expect "Loaded detection rules: N"
dist/sentinelclaw report --format json
```

The `report` run exercises the full deterministic scan and writes a
report file, proving the bundled rule data and the pipeline work in
the frozen binary.

## Release-time signing

Binary signing is a release-time step performed on the artifact that
was built on (and for) the target OS. It is intentionally not part of
the automated build:

**Windows (Authenticode)**
1. Build `sentinelclaw.exe` on Windows (CI artifact or
   `scripts/build_binary.ps1`).
2. Sign with a code-signing certificate, e.g. via
   `signtool sign /fd SHA256 /a dist\sentinelclaw.exe` (or Azure
   Trusted Signing / your CI code-signing service).
3. Optionally submit the signed binary to SmartScreen reputation
   (Microsoft Defender SmartScreen / submission portal).

**macOS (notarization)**
1. Build `sentinelclaw` on macOS.
2. Sign with `codesign --options runtime` using your Developer ID.
3. Notarize with `notarytool` and staple the ticket
   (`xcrun stapler staple`).

**Linux (GPG)**
1. Build `sentinelclaw` on Linux.
2. Sign the artifact and publish the signature alongside the release,
   e.g. `gpg --detach-sign --armor dist/sentinelclaw` and publish
   `dist/sentinelclaw.asc` plus the public key.

CI does not hold code-signing secrets by default; wire a signing step
into the release workflow when a certificate is available.

## Version bumps

Versions are maintained in `pyproject.toml` only. Before tagging a
release, bump with:

```bash
python scripts/bump_version.py --patch   # 0.1.0 -> 0.1.1
python scripts/bump_version.py --minor   # 0.1.0 -> 0.2.0
python scripts/bump_version.py --major   # 0.1.0 -> 1.0.0
python scripts/bump_version.py 1.2.3     # explicit target
```

The script rewrites only the `[project] version` line and prints the
old -> new versions. Commit the change and tag the release (for
example `v0.1.1`).

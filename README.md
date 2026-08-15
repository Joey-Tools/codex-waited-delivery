# Codex Waited Delivery

Historical and experimental child-and-wait delivery workflow tooling.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -I -B -c 'import sys; from pathlib import Path; paths=sorted(Path("skills/waited-delivery/scripts").glob("*.py")); sys.exit("no candidate Python helpers found") if not paths else None; [compile(path.read_bytes(), str(path), "exec") for path in paths]'
python3 -I -m unittest discover -s skills/waited-delivery/tests
```

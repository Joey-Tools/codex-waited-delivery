# Codex Waited Delivery

Historical and experimental child-and-wait delivery workflow tooling.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -I -X pycache_prefix=/tmp/codex-waited-delivery-pycache -m py_compile skills/waited-delivery/scripts/*.py
python3 -I -m unittest discover -s skills/waited-delivery/tests
```

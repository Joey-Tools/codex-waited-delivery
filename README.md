# Codex Waited Delivery

Historical and experimental child-and-wait delivery workflow tooling.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -I -B -c 'import sys; from pathlib import Path; paths=sorted(Path("skills/waited-delivery/scripts").glob("*.py")); sys.exit("no candidate Python helpers found") if not paths else None; [compile(path.read_bytes(), str(path), "exec") for path in paths]'
python3 -I -B -c 'import os,stat,subprocess,sys,tempfile; from pathlib import Path; checkout=Path.cwd().resolve(); cache=tempfile.TemporaryDirectory(prefix="codex-waited-delivery-pycache-"); cache_root=Path(cache.name).resolve(); metadata=cache_root.stat(); safe=(cache_root.is_absolute() and cache_root != checkout and checkout not in cache_root.parents and metadata.st_uid==os.geteuid() and stat.S_IMODE(metadata.st_mode)==0o700); completed=(subprocess.run([sys.executable,"-I","-B","-X","pycache_prefix="+str(cache_root),"-m","unittest","discover","-s","skills/waited-delivery/tests"],check=False) if safe else None); cache.cleanup(); sys.exit(125 if completed is None else completed.returncode)'
```

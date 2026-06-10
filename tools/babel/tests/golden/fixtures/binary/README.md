# Binary golden fixtures

Drop a small, real, **redistributable** binary sample here to activate a binary
golden case (see `../../cases.py` → `BINARY_CASES`). Until a fixture exists the
case skips cleanly with a reason.

| Case | File to add here | Runtime lib needed |
|------|------------------|--------------------|
| `evtx_security`   | `Security.evtx` | `python-evtx` (`Evtx`) |
| `lnk_recent`      | `recent.lnk`    | `LnkParse3` |
| `prefetch_app`    | `APP.pf`        | stdlib |
| `registry_ntuser` | `NTUSER.DAT`    | `regipy` |
| `mft_record`      | `MFT`           | stdlib |

After adding a fixture (and `pip install` the lib), generate the golden:

```bash
cd tools && BABEL_REGEN_GOLDEN=1 python -m pytest plugins/tests/test_golden_binary.py
```

Review the generated `expected/<id>.json` before committing — keep samples tiny
and free of real PII/secrets.

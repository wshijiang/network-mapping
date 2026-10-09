"""Export only field names from the public config (Python 3.11+)."""
from pathlib import Path
import tomllib


def fields(table, prefix=""):
    for key, value in table.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            yield from fields(value, path)
        else:
            yield path


root = Path(__file__).resolve().parent.parent
config = tomllib.loads((root / "config.toml").read_text())
(root / "src/public_config_fields.txt").write_text("\n".join(sorted(fields(config))) + "\n")

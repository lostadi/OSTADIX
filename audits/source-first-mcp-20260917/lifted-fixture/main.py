import json
from pathlib import Path

readings = json.loads(Path("readings.json").read_text())
print(json.dumps({
    "stations": sorted({row["station"] for row in readings}),
    "total": sum(row["count"] for row in readings),
    "rows": len(readings),
}))

import json
import tempfile
from pathlib import Path
from .column import write, project
body = json.loads(Path('data/sample.json').read_text())
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / 'amount.col'
    manifest = write(path, body['values'], page_rows=4)
    values, ranges = project(path, body['selection'])
    print(json.dumps({'values': values, 'ranges': ranges, 'stored_bytes': path.stat().st_size}, ensure_ascii=False))

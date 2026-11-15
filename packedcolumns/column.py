"""普通页目录与行投影。"""
import hashlib
import json
from pathlib import Path
from .plain import encode, decode
from .rangeio import Reader

def write(path, values, page_rows=128):
    if page_rows <= 0:
        raise ValueError('页行数须为正')
    path = Path(path)
    entries = []
    batch = []
    row = 0
    with path.open('wb') as stream:
        def flush():
            nonlocal row
            raw = encode(batch)
            entries.append({'row_start': row, 'rows': len(batch), 'offset': stream.tell(), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'codec': 'plain-1'})
            stream.write(raw)
            row += len(batch)
        for value in values:
            batch.append(value)
            if len(batch) == page_rows:
                flush()
                batch.clear()
        if batch:
            flush()
    manifest = {'format': 1, 'rows': row, 'pages': entries}
    path.with_suffix('.json').write_text(json.dumps(manifest))
    return manifest

def project(path, row_ids):
    path = Path(path)
    manifest = json.loads(path.with_suffix('.json').read_text())
    selected = list(row_ids)
    if any(type(row) is not int or row < 0 or row >= manifest['rows'] for row in selected):
        raise ValueError('选择行号越界')
    wanted = set(selected)
    result = {}
    source = Reader(path)
    for page in manifest['pages']:
        hits = wanted.intersection(range(page['row_start'], page['row_start']+page['rows']))
        if not hits:
            continue
        raw = source.read_at(page['offset'], page['bytes'])
        if hashlib.sha256(raw).hexdigest() != page['sha256']:
            raise ValueError('页目录摘要不符')
        values = decode(raw)
        for row in hits:
            result[row] = values[row-page['row_start']]
    return [result[row] for row in selected], source.ranges

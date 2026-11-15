"""普通页/自适应页目录、行投影与整页校验。"""
import hashlib
import json
from pathlib import Path
from .plain import encode as plain_encode, decode as plain_decode, MAGIC as PLAIN_MAGIC
from .adaptive import (
    encode_page, decode_page, SelectiveReader, PageFormatError,
    MAGIC as ADAPTIVE_MAGIC, DEFAULT_BLOCK_ROWS,
)
from .rangeio import Reader

CODEC_PLAIN = 'plain-1'
CODEC_ADAPTIVE = 'adaptive-2'


def _record(stream, row, batch, block_rows):
    """同一页分别用两种格式编码，按真实落盘字节竞标，返回目录项。"""
    raw_plain = plain_encode(batch)
    raw_adaptive = encode_page(batch, block_rows=block_rows)
    if len(raw_adaptive) < len(raw_plain):
        codec, raw = CODEC_ADAPTIVE, raw_adaptive
    else:
        codec, raw = CODEC_PLAIN, raw_plain
    offset = stream.tell()
    stream.write(raw)
    return {'row_start': row, 'rows': len(batch), 'offset': offset,
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'codec': codec}


def write(path, values, page_rows=128, block_rows=DEFAULT_BLOCK_ROWS):
    """流式写列：逐页缓冲、页内逐块决策，峰值内存与列长无关。"""
    if page_rows <= 0:
        raise ValueError('页行数须为正')
    if block_rows <= 0:
        raise ValueError('块行数须为正')
    path = Path(path)
    entries = []
    batch = []
    row = 0
    with path.open('wb') as stream:
        def flush():
            nonlocal row
            entries.append(_record(stream, row, batch, block_rows))
            row += len(batch)
        for value in values:
            batch.append(value)
            if len(batch) == page_rows:
                flush()
                batch = []
        if batch:
            flush()
    manifest = {'format': 2, 'rows': row, 'pages': entries}
    path.with_suffix('.json').write_text(json.dumps(manifest))
    return manifest


def _project_plain(path, page, hits, source):
    raw = source.read_at(page['offset'], page['bytes'])
    if hashlib.sha256(raw).hexdigest() != page['sha256']:
        raise ValueError('页目录摘要不符')
    if raw[:5] != PLAIN_MAGIC:
        raise ValueError('普通页魔数不符')
    values = plain_decode(raw)
    return {row: values[row - page['row_start']] for row in hits}


def _project_adaptive(path, page, hits, source):
    # 魔数与目录均由 SelectiveReader 在持久格式内自检，无需额外探测读
    reader = SelectiveReader(source, page)
    relative = {row - page['row_start']: row for row in hits}
    decoded = reader.read_rows(relative.keys())
    return {relative[rel]: value for rel, value in decoded.items()}


def project(path, row_ids):
    """按调用方次序返回选中行；只读取命中页/命中块，空选择不触发 IO。"""
    path = Path(path)
    manifest = json.loads(path.with_suffix('.json').read_text())
    selected = list(row_ids)
    if any(type(row) is not int or row < 0 or row >= manifest['rows'] for row in selected):
        raise ValueError('选择行号越界')
    wanted = set(selected)
    result = {}
    source = Reader(path)
    for page in manifest['pages']:
        hits = wanted.intersection(range(page['row_start'],
                                         page['row_start'] + page['rows']))
        if not hits:
            continue
        codec = page.get('codec', CODEC_PLAIN)  # 旧格式 1 的目录无 codec 字段
        if codec == CODEC_PLAIN:
            result.update(_project_plain(path, page, hits, source))
        elif codec == CODEC_ADAPTIVE:
            result.update(_project_adaptive(path, page, hits, source))
        else:
            raise ValueError('目录含未知 codec: %r' % codec)
    return [result[row] for row in selected], source.ranges


def verify(path):
    """整页强校验：逐页读取全部字节并核对 SHA256、页/块 CRC 与结构。

    与 project 的局部结论不同，这里对未读字节也给出明确结论。
    返回 (页数, 校验总字节)；任何损坏抛 PageFormatError/ValueError，
    PageFormatError 携带对象内真实绝对字节范围。
    """
    path = Path(path)
    manifest = json.loads(path.with_suffix('.json').read_text())
    source = Reader(path)
    total = 0
    for page in manifest['pages']:
        raw = source.read_at(page['offset'], page['bytes'])
        if hashlib.sha256(raw).hexdigest() != page['sha256']:
            raise PageFormatError('页目录摘要不符', page['offset'], page['bytes'])
        codec = page.get('codec', CODEC_PLAIN)
        if codec == CODEC_PLAIN:
            plain_decode(raw)
        elif codec == CODEC_ADAPTIVE:
            if raw[:5] != ADAPTIVE_MAGIC:
                raise PageFormatError('自适应页魔数不符', page['offset'], 5)
            decode_page(raw)
        else:
            raise ValueError('目录含未知 codec: %r' % codec)
        total += len(raw)
    return len(manifest['pages']), total

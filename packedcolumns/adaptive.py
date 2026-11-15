"""INTP2 自适应整数页：块级编码、目录定位与选择性解码。

页布局（小端）::

    magic 'INTP2'
    固定头: row_count u32, block_count u32, dir_size u32
    块目录（每项 17 字节）
    目录区 CRC32
    块 1 | 块 2 | ...
    整页 CRC32（覆盖其之前全部字节）

目录项：row_start u32, rows u32, block_offset u32（相对块区起点）,
block_size u32（块的全部持久字节，含块位图与块 CRC）, codec u8。

块持久字节：null 位图（rows 位，1=非空，末字节填充位为零）+ 编码载荷 +
CRC32(位图+载荷)。null 不占有效值序号：块只编码自身行区间内的非空值，
读取时由块位图把块内行号换算成有效值序号。位图随块存放，使空行定位只
读目标块，选择性读量严格按块有界，与页内行数无关。

所有差分用模 2**64 运算，跨完整 int64 范围也不会有符号减法溢出或截断。
"""
import bisect
import struct
import zlib

MAGIC = b'INTP2'

CODEC_CONST = 0      # 空块零载荷；否则单个 int64 常量
CODEC_PLAIN = 1      # n 个定宽 int64
CODEC_BITPACK = 2    # zigzag 后定宽位打包
CODEC_DELTA = 3      # 基值 + 模 2^64 相邻差定位打包
CODEC_DELTA_EXC = 4  # 基值 + 窄位宽差分流 + 例外位图/例外表

_KNOWN_CODECS = frozenset(range(5))
DEFAULT_BLOCK_ROWS = 64

INT64_MIN = -(2 ** 63)
INT64_MAX = 2 ** 63 - 1
_MASK64 = 2 ** 64 - 1

FIXED_HEADER_SIZE = 5 + 3 * 4          # magic + 三个 u32
DIR_ENTRY_SIZE = 4 * 4 + 1             # 四个 u32 + codec u8
DIR_CRC_SIZE = 4
BLOCK_CRC_SIZE = 4
PAGE_CRC_SIZE = 4


class PageFormatError(ValueError):
    """页结构或校验失败；start/size 为对象内真实绝对字节范围（未知时为 None）。"""

    def __init__(self, message, start=None, size=None):
        super().__init__(message)
        self.start = start
        self.size = size

    def detail(self):
        if self.start is None:
            return str(self)
        return f'{self.args[0]}（字节范围 [{self.start}, {self.start + self.size})）'


# --------------------------------------------------------------------------
# 基础换算
# --------------------------------------------------------------------------

def _check_int(value):
    # 严格拒绝 bool 与超界值，与 plain.py 的口径一致
    if type(value) is not int or not INT64_MIN <= value <= INT64_MAX:
        raise ValueError('整数列超界或类型不符')


def _zigzag(value):
    """有符号 int64 -> 无符号 64 位，结果恒在 [0, 2**64)。"""
    return (value << 1) ^ (value >> 63)


def _unzigzag(unsigned):
    return (unsigned >> 1) ^ -(unsigned & 1)


def _to_signed64(unsigned):
    return unsigned - (1 << 64) if unsigned >= (1 << 63) else unsigned


def _pack_words(words, width):
    """LSB 优先位打包；width=0 时所有词必须为 0，返回空字节。"""
    if width == 0:
        if any(words):
            raise PageFormatError('零位宽词非零')
        return b''
    accumulator = 0
    for index, word in enumerate(words):
        if word >> width:
            raise PageFormatError('位打包词超宽')
        accumulator |= word << (index * width)
    return accumulator.to_bytes((len(words) * width + 7) // 8, 'little')


def _unpack_words(buffer, count, width):
    if width == 0:
        if buffer:
            raise PageFormatError('零位宽流有余量')
        return [0] * count
    expected = (count * width + 7) // 8
    if len(buffer) != expected:
        raise PageFormatError('位打包流长度不符')
    if width == 64 and count:
        return list(struct.unpack('<%dQ' % count, buffer))
    accumulator = int.from_bytes(buffer, 'little')
    mask = (1 << width) - 1
    return [(accumulator >> (index * width)) & mask for index in range(count)]


def _popcount_range(bitmap, start, end):
    """位图 [start, end) 位区间内的置位数，start/end 为块内相对行号。"""
    if start >= end:
        return 0
    total = 0
    first_byte = start // 8
    last_byte = (end - 1) // 8
    for index in range(first_byte, last_byte + 1):
        byte = bitmap[index]
        low = max(0, start - index * 8)
        high = min(8, end - index * 8)
        keep = (0xFF >> (8 - high)) & ~((1 << low) - 1)
        total += (byte & keep).bit_count()
    return total


def _block_bitmap_size(rows):
    return (rows + 7) // 8


# --------------------------------------------------------------------------
# 块编码：候选按真实载荷字节竞标
# --------------------------------------------------------------------------

def _encode_block(values):
    """values 为块内全部非空 int（已校验），返回 (codec, payload)。"""
    n = len(values)
    if n == 0:
        # 空块规范表示：CONST 零载荷，块位图全零即可还原
        return CODEC_CONST, b''
    if n == 1:
        # 单值规范表示：CONST 单 int64，随机读取无需解包
        return CODEC_CONST, struct.pack('<q', values[0])

    candidates = []

    # 常量（多值全等时按真实字节参与竞标）
    if all(value == values[0] for value in values):
        candidates.append((8, CODEC_CONST, struct.pack('<q', values[0])))

    # 相邻差分：模 2^64 减法，极端差值也只落在 64 位内
    base = values[0]
    offsets = []
    previous = base
    for value in values[1:]:
        offsets.append((value - previous) & _MASK64)
        previous = value
    width = max((offset.bit_length() for offset in offsets), default=0)
    payload = struct.pack('<q', base) + bytes([width]) + _pack_words(offsets, width)
    candidates.append((len(payload), CODEC_DELTA, payload))

    # zigzag 定宽直打
    zigged = [_zigzag(value) for value in values]
    width = max(word.bit_length() for word in zigged)
    payload = bytes([width]) + _pack_words(zigged, width)
    candidates.append((len(payload), CODEC_BITPACK, payload))

    # 基值差分 + 例外表：离群值只付 8 字节例外价，不抬高整块位宽
    base = values[0]
    relative = [(value - base) & _MASK64 for value in values[1:]]
    best = None
    for width in range(64):  # 64 位宽时无例外可言，交给 DELTA/PLAIN
        exception_bitmap = bytearray((n + 7) // 8)
        for ordinal, offset in enumerate(relative, start=1):
            if offset.bit_length() > width:
                exception_bitmap[ordinal // 8] |= 1 << (ordinal % 8)
        exception_values = [values[ordinal]
                            for ordinal in range(1, n)
                            if exception_bitmap[ordinal // 8] & (1 << (ordinal % 8))]
        normals = [relative[ordinal - 1]
                   for ordinal in range(1, n)
                   if not (exception_bitmap[ordinal // 8] & (1 << (ordinal % 8)))]
        payload = (
            struct.pack('<q', base)
            + bytes([width])
            + struct.pack('<H', len(exception_values))
            + bytes(exception_bitmap)
            + _pack_words(normals, width)
            + b''.join(struct.pack('<q', value) for value in exception_values)
        )
        if best is None or len(payload) < len(best[2]):
            best = (len(payload), CODEC_DELTA_EXC, payload)
    candidates.append(best)

    # 定宽 int64 兜底，保证随机数据不膨胀
    payload = b''.join(struct.pack('<q', value) for value in values)
    candidates.append((len(payload), CODEC_PLAIN, payload))

    cost, codec, payload = min(candidates, key=lambda item: item[0])
    return codec, payload


def _decode_block(payload, codec, count):
    """还原块内 count 个非空 int；所有长度严格校验，拒绝多余字节。"""
    if count == 0:
        if codec != CODEC_CONST or payload:
            raise PageFormatError('空块编码不符')
        return []

    if codec == CODEC_CONST:
        if len(payload) != 8:
            raise PageFormatError('常量块长度不符')
        value = struct.unpack('<q', payload)[0]
        return [value] * count

    if codec == CODEC_PLAIN:
        if len(payload) != 8 * count:
            raise PageFormatError('PLAIN 块长度不符')
        return list(struct.unpack('<%dq' % count, payload))

    if codec == CODEC_BITPACK:
        if len(payload) < 1:
            raise PageFormatError('BITPACK 块缺位宽')
        width = payload[0]
        if width > 64:
            raise PageFormatError('位宽超界')
        words = _unpack_words(payload[1:], count, width)
        values = [_to_signed64(_unzigzag(word)) for word in words]
        if any(not INT64_MIN <= value <= INT64_MAX for value in values):
            raise PageFormatError('解码值超界')
        return values

    if codec == CODEC_DELTA:
        if len(payload) < 9:
            raise PageFormatError('DELTA 块过短')
        base = struct.unpack('<q', payload[:8])[0]
        width = payload[8]
        if width > 64:
            raise PageFormatError('位宽超界')
        packed_size = ((count - 1) * width + 7) // 8
        if len(payload) != 9 + packed_size:
            raise PageFormatError('DELTA 块长度不符')
        offsets = _unpack_words(payload[9:], count - 1, width)
        values = [base]
        current = base & _MASK64
        for offset in offsets:
            current = (current + offset) & _MASK64
            values.append(_to_signed64(current))
        return values

    if codec == CODEC_DELTA_EXC:
        if len(payload) < 11:
            raise PageFormatError('例外表块过短')
        base = struct.unpack('<q', payload[:8])[0]
        width = payload[8]
        if width > 63:
            raise PageFormatError('例外块位宽超界')
        exception_count = struct.unpack('<H', payload[9:11])[0]
        if exception_count > count - 1:
            raise PageFormatError('例外数超界')
        bitmap_size = (count + 7) // 8
        if len(payload) < 11 + bitmap_size:
            raise PageFormatError('例外位图截断')
        exception_bitmap = payload[11:11 + bitmap_size]
        if exception_bitmap[0] & 1:
            raise PageFormatError('基值不得为例外')
        if count % 8 and exception_bitmap[-1] >> (count % 8):
            raise PageFormatError('例外位图填充位非零')
        if _popcount_range(exception_bitmap, 0, count) != exception_count:
            raise PageFormatError('例外数与位图不符')
        cursor = 11 + bitmap_size
        normal_count = count - 1 - exception_count
        packed_size = (normal_count * width + 7) // 8
        normals = _unpack_words(payload[cursor:cursor + packed_size], normal_count, width)
        cursor += packed_size
        tail_size = 8 * exception_count
        if len(payload) != cursor + tail_size:
            raise PageFormatError('例外表块长度不符')
        exception_values = list(struct.unpack(
            '<%dq' % exception_count, payload[cursor:cursor + tail_size])) \
            if exception_count else []

        values = [base]
        normal_index = 0
        exception_index = 0
        base_unsigned = base & _MASK64
        for ordinal in range(1, count):
            if exception_bitmap[ordinal // 8] & (1 << (ordinal % 8)):
                values.append(exception_values[exception_index])
                exception_index += 1
            else:
                offset = normals[normal_index]
                normal_index += 1
                values.append(_to_signed64((base_unsigned + offset) & _MASK64))
        return values

    raise PageFormatError('未知块编码 %r' % (codec,))


# --------------------------------------------------------------------------
# 页编码
# --------------------------------------------------------------------------

def _build_bitmap(rows):
    bitmap = bytearray(_block_bitmap_size(len(rows)))
    for row, value in enumerate(rows):
        if value is not None:
            bitmap[row // 8] |= 1 << (row % 8)
    return bytes(bitmap)


def encode_page(rows, block_rows=DEFAULT_BLOCK_ROWS):
    """把一页原行（含 None）编码为 INTP2 字节；rows 为调用方按页缓冲的列表。"""
    if block_rows <= 0:
        raise ValueError('块行数须为正')
    row_count = len(rows)
    for value in rows:
        if value is not None:
            _check_int(value)

    descriptors = []
    body = bytearray()
    for block_start in range(0, row_count, block_rows):
        block_rows_actual = min(block_rows, row_count - block_start)
        block_slice = rows[block_start:block_start + block_rows_actual]
        bitmap = _build_bitmap(block_slice)
        block_values = [value for value in block_slice if value is not None]
        codec, payload = _encode_block(block_values)
        block_inner = bitmap + payload
        block_bytes = block_inner + struct.pack('<I', zlib.crc32(block_inner))
        descriptors.append((block_start, block_rows_actual,
                            len(body), len(block_bytes), codec))
        body.extend(block_bytes)

    directory = bytearray()
    for row_start, block_len, block_offset, block_size, codec in descriptors:
        directory.extend(struct.pack('<IIIIB', row_start, block_len,
                                     block_offset, block_size, codec))
    header = MAGIC + struct.pack('<III', row_count, len(descriptors), len(directory))
    prefix = header + bytes(directory)
    page = bytearray(prefix)
    page.extend(struct.pack('<I', zlib.crc32(prefix)))
    page.extend(body)
    page.extend(struct.pack('<I', zlib.crc32(bytes(page))))
    return bytes(page)


# --------------------------------------------------------------------------
# 页结构解析（全量解码与选择性读取共用的校验逻辑）
# --------------------------------------------------------------------------

def _parse_prefix(prefix, page_bytes, page_offset, absolute):
    """prefix 含 固定头+目录+目录CRC，返回解析上下文。"""
    def fail(message, start=0, size=None):
        if not absolute:
            start = size = None
        else:
            if size is None:
                size = len(prefix)
            start += page_offset
        raise PageFormatError(message, start, size)

    if len(prefix) < FIXED_HEADER_SIZE + DIR_CRC_SIZE:
        fail('INTP2 页过短')
    if prefix[:5] != MAGIC:
        fail('INTP2 魔数不符')
    row_count, block_count, dir_size = struct.unpack(
        '<III', prefix[5:FIXED_HEADER_SIZE])
    if len(prefix) != FIXED_HEADER_SIZE + dir_size + DIR_CRC_SIZE:
        fail('目录区长度不符')
    if dir_size % DIR_ENTRY_SIZE or block_count != dir_size // DIR_ENTRY_SIZE:
        fail('块目录项数不符')
    stored_crc = struct.unpack('<I', prefix[-DIR_CRC_SIZE:])[0]
    if zlib.crc32(prefix[:-DIR_CRC_SIZE]) != stored_crc:
        fail('目录区校验失败')

    entries = []
    cursor = FIXED_HEADER_SIZE
    for index in range(block_count):
        row_start, block_rows, block_offset, block_size, codec = struct.unpack(
            '<IIIIB', prefix[cursor:cursor + DIR_ENTRY_SIZE])
        if codec not in _KNOWN_CODECS:
            fail('未知块编码 %r' % codec)
        if block_size < _block_bitmap_size(block_rows) + BLOCK_CRC_SIZE:
            fail('块物理长度不足以容纳位图与校验')
        entries.append({'row_start': row_start, 'rows': block_rows,
                        'block_offset': block_offset, 'block_size': block_size,
                        'codec': codec})
        cursor += DIR_ENTRY_SIZE

    # 行区间必须无缝覆盖整页
    expected_start = 0
    for entry in entries:
        if entry['row_start'] != expected_start or entry['rows'] == 0:
            fail('块行区间不连续')
        expected_start += entry['rows']
    if expected_start != row_count:
        fail('块行区间未覆盖整页')

    block_base = len(prefix)
    expected_offset = 0
    for entry in entries:
        if entry['block_offset'] != expected_offset:
            fail('块物理偏移不连续')
        expected_offset += entry['block_size']
    # 块区之后只剩整页 CRC
    if block_base + expected_offset + PAGE_CRC_SIZE != page_bytes:
        fail('块区物理范围不符')

    return {
        'row_count': row_count,
        'entries': entries,
        'block_base': block_base,
        'prefix_size': len(prefix),
    }


def _split_block(block_bytes, entry, page_offset, block_abs_start):
    """切出块位图与载荷并校验块 CRC，锚定真实绝对字节范围。"""
    span = entry['block_size']
    if len(block_bytes) != span:
        raise PageFormatError('块读取被截断', block_abs_start, span)
    stored_crc = struct.unpack('<I', block_bytes[-BLOCK_CRC_SIZE:])[0]
    inner = block_bytes[:-BLOCK_CRC_SIZE]
    if zlib.crc32(inner) != stored_crc:
        raise PageFormatError('块校验失败', block_abs_start, span)
    bitmap_size = _block_bitmap_size(entry['rows'])
    bitmap = inner[:bitmap_size]
    if entry['rows'] % 8 and bitmap and bitmap[-1] >> (entry['rows'] % 8):
        raise PageFormatError('块位图填充位非零', block_abs_start, span)
    payload = inner[bitmap_size:]
    return bitmap, payload


def decode_page(raw):
    """全量解码一页，返回含 None 的原行列表；校验整页 CRC 与每个块 CRC。"""
    if len(raw) < FIXED_HEADER_SIZE + DIR_CRC_SIZE + PAGE_CRC_SIZE:
        raise PageFormatError('INTP2 页过短')
    if raw[:5] != MAGIC:
        raise PageFormatError('INTP2 魔数不符')
    stored_page_crc = struct.unpack('<I', raw[-PAGE_CRC_SIZE:])[0]
    if zlib.crc32(raw[:-PAGE_CRC_SIZE]) != stored_page_crc:
        raise PageFormatError('整页校验失败')
    row_count, _, dir_size = struct.unpack('<III', raw[5:FIXED_HEADER_SIZE])
    prefix_end = FIXED_HEADER_SIZE + dir_size + DIR_CRC_SIZE
    context = _parse_prefix(raw[:prefix_end], len(raw), 0, absolute=False)

    output = [None] * row_count
    base = context['block_base']
    for entry in context['entries']:
        start = base + entry['block_offset']
        block_bytes = raw[start:start + entry['block_size']]
        bitmap, payload = _split_block(block_bytes, entry, 0, start)
        non_null = _popcount_range(bitmap, 0, entry['rows'])
        try:
            values = _decode_block(payload, entry['codec'], non_null)
        except PageFormatError:
            raise
        value_index = 0
        for local_row in range(entry['rows']):
            if bitmap[local_row // 8] & (1 << (local_row % 8)):
                output[entry['row_start'] + local_row] = values[value_index]
                value_index += 1
        if value_index != non_null:
            raise PageFormatError('块有效值数不符')
    return output


# --------------------------------------------------------------------------
# 选择性读取：仅读目录前缀与命中块，局部校验结论不波及未读字节
# --------------------------------------------------------------------------

def _coalesce(intervals):
    """合并相邻/重叠的 (start, size) 区间，减少真实范围读次数。"""
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged = [list(intervals[0])]
    for start, size in intervals[1:]:
        last_start = merged[-1][0]
        last_end = last_start + merged[-1][1]
        if start <= last_end:
            merged[-1][1] = max(last_end, start + size) - last_start
        else:
            merged.append([start, size])
    return [(start, size) for start, size in merged]


class SelectiveReader:
    """对单个 INTP2 页做块级稀疏读取；source 需提供 read_at(start, size)。

    若 source 带 size 属性（rangeio.Reader 即如此），将用真实对象大小做
    结构边界校验，使截断在目录解析阶段就暴露，而不是拖到块读取。
    """

    def __init__(self, source, page):
        self.source = source
        self.page_offset = page['offset']
        self.page_bytes = page['bytes']
        self.object_size = getattr(source, 'size', None)
        self._context = None

    def _read_absolute(self, start, size):
        if start < self.page_offset or size < 0 or \
                start + size > self.page_offset + self.page_bytes:
            raise PageFormatError('范围读越过页边界', start, size)
        return self.source.read_at(start, size)

    def _load_prefix(self):
        if self._context is not None:
            return
        if self.page_bytes < FIXED_HEADER_SIZE + DIR_CRC_SIZE + PAGE_CRC_SIZE:
            raise PageFormatError('INTP2 页过短', self.page_offset, self.page_bytes)
        head = self._read_absolute(self.page_offset, FIXED_HEADER_SIZE)
        if head[:5] != MAGIC:
            raise PageFormatError('INTP2 魔数不符', self.page_offset, FIXED_HEADER_SIZE)
        _, _, dir_size = struct.unpack('<III', head[5:FIXED_HEADER_SIZE])
        rest = self._read_absolute(
            self.page_offset + FIXED_HEADER_SIZE, dir_size + DIR_CRC_SIZE)
        prefix = head + rest
        if self.object_size is not None and \
                self.page_offset + self.page_bytes > self.object_size:
            raise PageFormatError(
                '页范围越过对象结尾', self.object_size,
                self.page_offset + self.page_bytes - self.object_size)
        context = _parse_prefix(prefix, self.page_bytes, self.page_offset, absolute=True)
        self._context = context

    @property
    def context(self):
        self._load_prefix()
        return self._context

    def read_rows(self, relative_rows):
        """读页内相对行号集合，返回 {相对行号: 值或 None}，只触碰必要字节。"""
        relative_rows = list(relative_rows)
        if not relative_rows:
            return {}  # 空选择零 IO，不读目录也不读块
        self._load_prefix()
        context = self._context
        row_count = context['row_count']
        entries = context['entries']
        block_starts = [entry['row_start'] for entry in entries]

        result = {}
        hits = {}
        for row in relative_rows:
            if type(row) is not int or not 0 <= row < row_count:
                raise PageFormatError('页内行号越界', self.page_offset, self.page_bytes)
            index = bisect.bisect_right(block_starts, row) - 1
            hits.setdefault(index, set()).add(row)

        if hits:
            base = context['block_base']
            intervals = []
            for index in hits:
                entry = entries[index]
                rel_start = base + entry['block_offset']
                intervals.append((rel_start, entry['block_size']))
            buffers = {}
            for rel_start, size in _coalesce(intervals):
                buffers[rel_start] = self._read_absolute(
                    self.page_offset + rel_start, size)

            for index, rows in hits.items():
                entry = entries[index]
                rel_start = base + entry['block_offset']
                merged_start = max(start for start in buffers if start <= rel_start)
                merged = buffers[merged_start]
                cut = rel_start - merged_start
                block_bytes = merged[cut:cut + entry['block_size']]
                abs_start = self.page_offset + rel_start
                bitmap, payload = _split_block(block_bytes, entry,
                                               self.page_offset, abs_start)
                try:
                    values = _decode_block(payload, entry['codec'],
                                           _popcount_range(bitmap, 0, entry['rows']))
                except PageFormatError as error:
                    # 块内结构错误也锚定到真实字节范围
                    raise PageFormatError(str(error), abs_start,
                                          entry['block_size']) from None
                for row in rows:
                    local_row = row - entry['row_start']
                    if not (bitmap[local_row // 8] & (1 << (local_row % 8))):
                        result[row] = None
                        continue
                    ordinal = _popcount_range(bitmap, 0, local_row)
                    result[row] = values[ordinal]
        return result

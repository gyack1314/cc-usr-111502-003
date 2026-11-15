import bisect
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from packedcolumns import adaptive
from packedcolumns.adaptive import (
    encode_page, decode_page, SelectiveReader, PageFormatError,
    _encode_block, _decode_block, _block_bitmap_size,
    CODEC_CONST, CODEC_PLAIN, CODEC_BITPACK, CODEC_DELTA, CODEC_DELTA_EXC,
    MAGIC, FIXED_HEADER_SIZE, DIR_ENTRY_SIZE, DIR_CRC_SIZE,
    BLOCK_CRC_SIZE, PAGE_CRC_SIZE,
)
from packedcolumns import column
from packedcolumns.column import write, project, verify, CODEC_ADAPTIVE, CODEC_PLAIN
from packedcolumns.plain import encode as plain_encode, MAGIC as PLAIN_MAGIC


class FakeSource:
    """只服务给定字节的范围读源，并计量真实读取区间。"""

    def __init__(self, data, base=0):
        self.data = data
        self.base = base
        self.size = base + len(data)
        self.ranges = []
        self.bytes_read = 0

    def read_at(self, start, size):
        local = start - self.base
        if local < 0 or size < 0 or local + size > len(self.data):
            raise ValueError('范围读越界')
        value = self.data[local:local + size]
        if len(value) != size:
            raise ValueError('读取被截断')
        self.ranges.append((start, size))
        self.bytes_read += size
        return value


class BlockCodecTests(unittest.TestCase):
    def _roundtrip(self, values, codec=None):
        chosen, payload = _encode_block(list(values))
        if codec is not None:
            self.assertEqual(chosen, codec, f'期望 codec {codec}，实际 {chosen}')
        return _decode_block(payload, chosen, len(values))

    def test_each_codec_roundtrip(self):
        # 各 codec 用显式构造的规范载荷验证解码器，选择逻辑另由竞标测试覆盖
        explicit = {
            CODEC_CONST: (struct.pack('<q', 7), [7, 7, 7, 7]),
            CODEC_BITPACK: None,
            CODEC_DELTA: None,
            CODEC_DELTA_EXC: None,
        }
        payload, expected = explicit[CODEC_CONST]
        self.assertEqual(_decode_block(payload, CODEC_CONST, len(expected)), expected)
        for values in (
            [1, 2, 4, 8, 16, 32, 64],
            [1000, 1001, 1002, 1003, 1004],
            [100, 101, 102, 103, 2 ** 62, 105, 106],
        ):
            chosen, payload = _encode_block(values)
            self.assertEqual(_decode_block(payload, chosen, len(values)), values)

    def test_constant_payload_layout(self):
        codec, payload = _encode_block([7])
        self.assertEqual(codec, CODEC_CONST)
        self.assertEqual(payload, struct.pack('<q', 7))
        # 多值常量即便竞标给了更窄的表示，常量解码路径仍须成立
        self.assertEqual(
            _decode_block(struct.pack('<q', 7), CODEC_CONST, 4), [7] * 4)

    def test_codec_selection_is_cost_driven(self):
        # 单值/空值只有常量表示可行
        self.assertEqual(_encode_block([9])[0], CODEC_CONST)
        self.assertEqual(_encode_block([])[0], CODEC_CONST)
        # 大基值的平滑序列：直打位宽被基值抬高，差分必然胜出
        base = 10 ** 15
        self.assertEqual(
            _encode_block([base + i for i in range(12)])[0], CODEC_DELTA)
        # 离群值只进例外表，不抬高整块位宽
        self.assertEqual(
            _encode_block([100, 101, 102, 2 ** 62, 104, 105])[0], CODEC_DELTA_EXC)
        # 随机数据退化为直打或定宽，不会误用差分/例外
        randomish = [((i * 7919) ^ 0x5A5A) % 997 - 498 for i in range(12)]
        self.assertIn(_encode_block(randomish)[0], (CODEC_BITPACK, CODEC_PLAIN))
        # 多值常量无论哪个表示中标都须逐位往返
        codec, payload = _encode_block([9, 9, 9, 9])
        self.assertEqual(_decode_block(payload, codec, 4), [9, 9, 9, 9])

    def test_empty_and_single_blocks(self):
        codec, payload = _encode_block([])
        self.assertEqual(_decode_block(payload, codec, 0), [])
        codec, payload = _encode_block([-5])
        self.assertEqual(codec, CODEC_CONST)
        self.assertEqual(_decode_block(payload, codec, 1), [-5])

    def test_int64_extremes_and_extreme_deltas(self):
        values = [-(2 ** 63), 2 ** 63 - 1, -(2 ** 63), 0, -1, 2 ** 63 - 1]
        self.assertEqual(self._roundtrip(values), values)
        # 差分跨越整个 int64 跨度，有符号减法必然溢出，模 2^64 表示仍准确
        values = [0, 2 ** 63 - 1, -(2 ** 63), -1, 0]
        self.assertEqual(self._roundtrip(values), values)
        # 例外编码：窄流 + 极端离群
        values = [5, 6, 7, 8, -(2 ** 63), 2 ** 63 - 1, 9]
        self.assertEqual(self._roundtrip(values, CODEC_DELTA_EXC), values)

    def test_outlier_does_not_poison_width(self):
        values = [100 + i for i in range(20)] + [2 ** 62] + [121, 122]
        codec, payload = _encode_block(values)
        self.assertEqual(codec, CODEC_DELTA_EXC)
        self.assertEqual(_decode_block(payload, codec, len(values)), values)

    def test_corrupt_block_payload_caught(self):
        values = [((i * 7919) ^ 0x5A5A) % 997 - 498 for i in range(12)]
        codec, payload = _encode_block(values)
        # 逐字节尝试翻转：至少一种破坏必须触发结构或长度校验失败
        for pos in range(len(payload)):
            broken = payload[:pos] + bytes([payload[pos] ^ 0x01]) + payload[pos + 1:]
            try:
                decoded = _decode_block(broken, codec, len(values))
            except PageFormatError:
                return
        # 所有翻转都恰好保持合法的概率为零；兜底再用截断破坏
        with self.assertRaises(PageFormatError):
            _decode_block(payload[:-1], codec, len(values))


class PageRoundTripTests(unittest.TestCase):
    def test_nulls_keep_ordinal_and_extremes(self):
        rows = [None, -(2 ** 63), 2 ** 63 - 1, 0, None, 1, -1, None, 9]
        raw = encode_page(rows, block_rows=3)
        self.assertEqual(raw[:5], MAGIC)
        self.assertEqual(decode_page(raw), rows)
        self.assertEqual(decode_page(encode_page([None] * 12, 4)), [None] * 12)
        self.assertEqual(decode_page(encode_page([], 4)), [])

    def test_type_and_range_rejected(self):
        for bad in ([True], [2 ** 63], [-(2 ** 63) - 1], [1.0], ['x']):
            with self.assertRaises(ValueError):
                encode_page(bad)

    def test_bitmap_padding_must_be_zero(self):
        # 位图随块存放：第一个块紧跟目录区 CRC 之后
        raw = bytearray(encode_page([1, None, 2], 8))
        context = SelectiveReader(
            FakeSource(bytes(raw)), {'offset': 0, 'bytes': len(raw)}).context
        block0 = context['block_base']
        raw[block0] |= 0b11111000  # 3 行块的位图高 5 个填充位
        with self.assertRaises(PageFormatError):
            decode_page(bytes(raw))

    def test_fuzz_random_pages(self):
        import random
        rng = random.Random(20261116)
        for trial in range(60):
            count = rng.randrange(0, 300)
            rows = []
            for _ in range(count):
                roll = rng.random()
                if roll < 0.25:
                    rows.append(None)
                elif roll < 0.55:
                    rows.append(rng.randrange(-50, 50))            # 平滑小值
                elif roll < 0.75:
                    rows.append(rng.choice([0, 1, -1]))            # 常量倾向
                elif roll < 0.9:
                    rows.append(rng.randrange(-(2 ** 32), 2 ** 32))
                else:
                    rows.append(rng.randrange(-(2 ** 63), 2 ** 63))  # 离群大数
            block_rows = rng.choice([1, 2, 7, 16, 64, 128])
            raw = encode_page(rows, block_rows=block_rows)
            self.assertEqual(decode_page(raw), rows, f'fuzz trial {trial} 失败')

    def test_never_worse_than_plain_via_page_chooser(self):
        # 列层按真实总字节竞标：随机数据回退 plain，页级开销不会带来膨胀
        import random
        rng = random.Random(7)
        rows = [rng.randrange(-(2 ** 63), 2 ** 63) for _ in range(256)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'rnd.col'
            manifest = write(path, rows, page_rows=256, block_rows=64)
            self.assertLessEqual(
                manifest['pages'][0]['bytes'], len(plain_encode(rows)))
            self.assertEqual(manifest['pages'][0]['codec'], CODEC_PLAIN)


class SelectiveReadTests(unittest.TestCase):
    def setUp(self):
        self.rows = [None, 100, 101, 102, 103, None,
                     4611686018427387904, -4611686018427387904, 0,
                     None, 5, 5, 5, None, 7, 8]
        self.raw = encode_page(self.rows, block_rows=4)
        self.page = {'offset': 1000, 'bytes': len(self.raw)}
        self.source = FakeSource(self.raw, base=1000)

    def test_selection_across_nulls_and_block_borders(self):
        reader = SelectiveReader(self.source, self.page)
        picked = [15, 0, 6, 7, 8, 1, 5, 9, 12, 3, 3, 14]
        decoded = reader.read_rows(picked)
        self.assertEqual({row: self.rows[row] for row in set(picked)}, decoded)

    def test_only_null_rows_need_no_value_decode(self):
        source = FakeSource(self.raw, base=1000)
        reader = SelectiveReader(source, self.page)
        decoded = reader.read_rows([0, 5, 9, 13])
        self.assertEqual(decoded, {0: None, 5: None, 9: None, 13: None})
        # 空行只在命中块的位图内判定：读取范围只能落在命中块，不得读其他块
        context = reader.context
        hit_indices = set()
        starts = [e['row_start'] for e in context['entries']]
        for row in (0, 5, 9, 13):
            hit_indices.add(bisect.bisect_right(starts, row) - 1)
        prefix_end = 1000 + context['block_base']
        for start, size in source.ranges:
            if start + size <= prefix_end:
                continue  # 目录前缀读，不含任何块字节
            rel = start - 1000
            self.assertTrue(
                any(context['block_base'] + context['entries'][i]['block_offset']
                    <= rel
                    < context['block_base']
                    + context['entries'][i]['block_offset']
                    + context['entries'][i]['block_size']
                    for i in hit_indices))

    def test_read_volume_bounded_by_touched_blocks(self):
        source = FakeSource(self.raw, base=1000)
        reader = SelectiveReader(source, self.page)
        reader.read_rows([15])
        context = reader.context
        block_count = len(context['entries'])
        touched = sum(size for _, size in source.ranges)
        self.assertLess(touched, len(self.raw))
        # 读量上界：目录 + 单个命中块，与块总数/页行数无关
        last = context['entries'][-1]
        bound = context['block_base'] + last['block_size']
        self.assertLessEqual(touched, bound)
        self.assertGreater(block_count, 1)

    def test_sparse_null_page_read_is_block_bounded(self):
        # 长 null 列：定位单个空行只读目录 + 一个小块；
        # 块大小固定时，块载荷读量不随行数增长（目录仅随块数线性）
        rows = [None] * 4000
        raw = encode_page(rows, 128)
        source = FakeSource(raw)
        SelectiveReader(source, {'offset': 0, 'bytes': len(raw)}).read_rows([3999])
        context = SelectiveReader(
            FakeSource(raw), {'offset': 0, 'bytes': len(raw)}).context
        single_block = max(e['block_size'] for e in context['entries'])
        # 目录 + 至多一个块的有界上界
        self.assertLessEqual(
            source.bytes_read, context['block_base'] + single_block)
        # 块位图本身仅 ceil(128/8)=16 字节，远小于整页
        self.assertEqual(_block_bitmap_size(128), 16)
        self.assertLess(single_block, 40)

    def test_prefix_crc_corruption_localized(self):
        broken = bytearray(self.raw)
        broken[FIXED_HEADER_SIZE] ^= 0x01  # 目录区字节翻转
        source = FakeSource(bytes(broken), base=1000)
        reader = SelectiveReader(source, self.page)
        with self.assertRaises(PageFormatError) as caught:
            reader.read_rows([1])
        error = caught.exception
        self.assertIsNotNone(error.start)
        self.assertEqual(error.start, 1000)
        self.assertGreater(error.size, 0)
        self.assertLessEqual(error.start + error.size, 1000 + len(self.raw))

    def test_block_crc_corruption_reports_real_range(self):
        reader = SelectiveReader(FakeSource(self.raw, base=1000), self.page)
        context = reader.context
        entry = context['entries'][1]
        block_start = 1000 + context['block_base'] + entry['block_offset']
        broken = bytearray(self.raw)
        local = context['block_base'] + entry['block_offset']
        broken[local] ^= 0xFF
        source = FakeSource(bytes(broken), base=1000)
        with self.assertRaises(PageFormatError) as caught:
            SelectiveReader(source, self.page).read_rows(
                [entry['row_start'], entry['row_start'] + 1])
        error = caught.exception
        self.assertEqual(error.start, block_start)
        self.assertEqual(error.size, entry['block_size'])

    def test_page_crc_not_required_for_local_read_but_full_decode_catches(self):
        # 篡改整页 CRC：选择性读不依赖它，仍能正确返回；全量解码必须拒绝
        broken = bytearray(self.raw)
        broken[-1] ^= 0x01
        source = FakeSource(bytes(broken), base=1000)
        reader = SelectiveReader(source, self.page)
        self.assertEqual(reader.read_rows([1, 8]), {1: 100, 8: 0})
        with self.assertRaises(PageFormatError):
            decode_page(bytes(broken))

    def test_truncated_page_rejected(self):
        # 目录前缀长度约二十字节，截断到它之前必然报错；尾部截断破坏块区范围
        prefix_size = SelectiveReader(
            FakeSource(self.raw, base=1000), self.page).context['prefix_size']
        for cut in (5, FIXED_HEADER_SIZE, prefix_size - 1, len(self.raw) - 8):
            if cut <= 0:
                continue
            source = FakeSource(self.raw[:cut], base=1000)
            with self.assertRaises((PageFormatError, ValueError)):
                SelectiveReader(source, self.page).read_rows([1])

    def test_unknown_codec_in_directory_rejected(self):
        raw = bytearray(self.raw)
        # 目录项紧跟固定头，每项末字节是 codec
        codec_pos = FIXED_HEADER_SIZE + DIR_ENTRY_SIZE - 1
        raw[codec_pos] = 99
        with self.assertRaises(PageFormatError):
            decode_page(bytes(raw))


class ColumnIntegrationTests(unittest.TestCase):
    def test_mixed_codec_pages_and_legacy_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            # 平滑页应压缩为 adaptive；全离群页在块级退化后由列层回退 plain
            smooth = list(range(100, 140))
            outliers = [((-1) ** i) * (2 ** 62 + i) for i in range(40)]
            manifest = write(path, smooth + outliers, page_rows=40, block_rows=10)
            codecs = [page['codec'] for page in manifest['pages']]
            self.assertEqual(codecs[0], CODEC_ADAPTIVE)
            # 离群页：块内仍可用差分/例外表示，若 adaptive 总字节不占优则必须回退
            adaptive_candidate = encode_page(outliers, 10)
            self.assertEqual(
                codecs[1],
                CODEC_PLAIN if len(plain_encode(outliers)) <= len(adaptive_candidate)
                else CODEC_ADAPTIVE)
            values, ranges = project(path, [0, 39, 40, 79, 20])
            self.assertEqual(values, [100, 139, smooth.__len__() and outliers[0],
                                      outliers[-1], 120])
            # 旧格式 1 目录（无 codec 字段）仍按 plain 读
            legacy = {'format': 1, 'rows': 3, 'pages': [{
                'row_start': 0, 'rows': 3, 'offset': 0,
                'bytes': 0, 'sha256': '',
            }]}
            raw = plain_encode([None, 7, -7])
            legacy['pages'][0].update(bytes=len(raw),
                                      sha256=hashlib.sha256(raw).hexdigest())
            legacy_path = Path(tmp) / 'legacy.col'
            legacy_path.write_bytes(raw)
            legacy_path.with_suffix('.json').write_text(json.dumps(legacy))
            self.assertEqual(project(legacy_path, [2, 1, 0, 2])[0], [-7, 7, None, -7])

    def test_sparse_read_skips_pages_and_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            rows = [None] + list(range(100, 200)) + [None] + list(range(200, 400))
            self.assertEqual(len(rows), 302)
            manifest = write(path, rows, page_rows=50, block_rows=10)
            # 选中间页中间块的一行：跳过整页之外，页内也只读一个小块
            target_row = 77
            values, ranges = project(path, [target_row])
            self.assertEqual(values, [rows[target_row]])
            self.assertNotIn((manifest['pages'][0]['offset'],
                              manifest['pages'][0]['bytes']), ranges)
            hit_page = next(p for p in manifest['pages']
                            if p['row_start'] <= target_row
                            < p['row_start'] + p['rows'])
            # 目录前缀 + 单块，读量严格小于整页（页含多个块）
            self.assertLess(sum(size for _, size in ranges), hit_page['bytes'])

    def test_corruption_error_carries_absolute_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            write(path, list(range(60)), page_rows=30, block_rows=5)
            manifest = json.loads(path.with_suffix('.json').read_text())
            page = manifest['pages'][0]
            data = bytearray(path.read_bytes())
            local = page['offset'] + page['bytes'] - 8
            data[local] ^= 0x01
            path.write_bytes(data)
            with self.assertRaises(PageFormatError) as caught:
                project(path, [29])
            error = caught.exception
            self.assertIsNotNone(error.start)
            self.assertGreaterEqual(error.start, page['offset'])
            self.assertLess(error.start + error.size,
                            page['offset'] + page['bytes'] + 1)

    def test_verify_full_page_strength_and_sha_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            rows = [None, 1, 2, 3] + list(range(-50, 50)) + [2 ** 63 - 1, -(2 ** 63)]
            manifest = write(path, rows, page_rows=16, block_rows=4)
            pages, total = verify(path)
            self.assertEqual(pages, len(manifest['pages']))
            self.assertEqual(total, sum(p['bytes'] for p in manifest['pages']))
            # 改一个未被任何选择触及的字节：project 可能不报错，verify 必须报
            data = bytearray(path.read_bytes())
            page = manifest['pages'][0]
            data[page['offset'] + page['bytes'] - 1] ^= 0x80
            path.write_bytes(data)
            with self.assertRaises((PageFormatError, ValueError)):
                verify(path)

    def test_streaming_write_bounded_peak(self):
        # 用海量迭代器写列：写路径只能持有当前页/块缓冲，不能整列入内存
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'long.col'
            target = 200_000

            def generator():
                for i in range(target):
                    yield None if i % 97 == 0 else (i % 1000) - 500

            manifest = write(path, generator(), page_rows=512, block_rows=64)
            self.assertEqual(manifest['rows'], target)
            picked = [0, 96, target - 1, target // 2, 1]
            values, ranges = project(path, picked)
            expected = [None if i % 97 == 0 else (i % 1000) - 500 for i in picked]
            self.assertEqual(values, expected)
            self.assertLess(sum(size for _, size in ranges),
                            sum(p['bytes'] for p in manifest['pages']))

    def test_compression_gains_on_realistic_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            # 平滑消费金额 + 少量异常大额 + 稀疏 null
            rows = []
            for i in range(2000):
                if i % 53 == 0:
                    rows.append(None)
                elif i % 211 == 0:
                    rows.append(2 ** 60 + i)
                else:
                    rows.append(10000 + (i % 7) - 3)
            manifest = write(path, rows, page_rows=256, block_rows=32)
            adaptive_bytes = sum(p['bytes'] for p in manifest['pages'])
            # 同分页口径下的定宽 INTP1 总字节
            fixed_width_bytes = sum(
                len(plain_encode(rows[start:start + 256]))
                for start in range(0, len(rows), 256))
            self.assertLess(adaptive_bytes, fixed_width_bytes * 0.4)
            self.assertTrue(any(p['codec'] == CODEC_ADAPTIVE
                                for p in manifest['pages']))
            # 逐行全量投影与原数据逐位一致
            self.assertEqual(project(path, list(range(len(rows))))[0], rows)

    def test_empty_column_and_empty_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'empty.col'
            write(path, [], 8)
            self.assertEqual(project(path, [])[0], [])
            with self.assertRaises(ValueError):
                project(path, [0])


if __name__ == '__main__':
    unittest.main()

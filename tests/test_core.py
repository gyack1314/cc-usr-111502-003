import tempfile
import unittest
from pathlib import Path
from packedcolumns.plain import encode, decode
from packedcolumns.column import write, project

class CoreTests(unittest.TestCase):
    def test_full_range_and_null_bitmap(self):
        values = [None, -(2**63), 2**63-1, 0, None, 1, -1, None, 9]
        self.assertEqual(decode(encode(values)), values)
        self.assertEqual(decode(encode([None]*10)), [None]*10)
        for values in [[True], [2**63]]:
            with self.assertRaises(ValueError):
                encode(values)

    def test_selected_order_duplicates_and_page_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            manifest = write(path, iter([None, 1, 2, 3, 4, None, 6, 7, 8]), 3)
            values, ranges = project(path, [8, 0, 8])
            self.assertEqual(values, [8, None, 8])
            self.assertEqual(len(ranges), 2)
            self.assertNotIn((manifest['pages'][1]['offset'], manifest['pages'][1]['bytes']), ranges)

    def test_corruption_and_projection_bounds(self):
        raw = bytearray(encode([1, None, 2]))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            decode(bytes(raw))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'amount.col'
            write(path, [], 2)
            self.assertEqual(project(path, [])[0], [])
            with self.assertRaises(ValueError):
                project(path, [0])

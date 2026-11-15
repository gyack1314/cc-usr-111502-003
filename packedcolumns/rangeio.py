"""落盘对象的真实范围读。"""
from pathlib import Path

class Reader:
    def __init__(self, path):
        self.path = Path(path)
        self.size = self.path.stat().st_size
        self.ranges = []
        self.bytes_read = 0

    def read_at(self, start, size):
        if start < 0 or size < 0 or start+size > self.size:
            raise ValueError('范围读越界')
        with self.path.open('rb') as stream:
            stream.seek(start)
            value = stream.read(size)
        if len(value) != size:
            raise ValueError('对象读取被截断')
        self.ranges.append((start, size))
        self.bytes_read += len(value)
        return value

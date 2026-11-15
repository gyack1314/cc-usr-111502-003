"""当前普通整数叶页。"""
import struct
import zlib
MAGIC = b'INTP1'

def encode(values):
    values = list(values)
    bitmap = bytearray((len(values) + 7) // 8)
    payload = bytearray()
    for row, value in enumerate(values):
        if value is None:
            continue
        if type(value) is not int or not -(2**63) <= value < 2**63:
            raise ValueError('整数列超界或类型不符')
        bitmap[row//8] |= 1 << (row%8)
        payload.extend(struct.pack('<q', value))
    body = MAGIC + struct.pack('<II', len(values), len(bitmap)) + bytes(bitmap) + bytes(payload)
    return body + struct.pack('<I', zlib.crc32(body))

def decode(raw):
    if len(raw) < 17 or raw[:5] != MAGIC:
        raise ValueError('普通页格式无效')
    if zlib.crc32(raw[:-4]) != struct.unpack('<I', raw[-4:])[0]:
        raise ValueError('普通页校验失败')
    count, bitmap_size = struct.unpack('<II', raw[5:13])
    if bitmap_size != (count+7)//8 or 13+bitmap_size+4 > len(raw):
        raise ValueError('位图长度不符')
    bitmap = raw[13:13+bitmap_size]
    if count%8 and bitmap and bitmap[-1] >> (count%8):
        raise ValueError('位图填充位非零')
    offset = 13+bitmap_size
    output = []
    for row in range(count):
        if bitmap[row//8] & (1 << (row%8)):
            if offset+8 > len(raw)-4:
                raise ValueError('有效值被截断')
            output.append(struct.unpack('<q', raw[offset:offset+8])[0])
            offset += 8
        else:
            output.append(None)
    if offset != len(raw)-4:
        raise ValueError('普通页有多余数据')
    return output

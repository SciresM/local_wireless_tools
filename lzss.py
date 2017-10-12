# adapted from http://code.google.com/p/dsdecmp/source/browse/trunk/CSharp/DSDecmp/Program.cs
import sys
from struct import pack, unpack
from cStringIO import StringIO
from array import array

class DecompressionError(ValueError):
    pass

def bits(byte):
    return ((byte >> 7) & 1,
            (byte >> 6) & 1,
            (byte >> 5) & 1,
            (byte >> 4) & 1,
            (byte >> 3) & 1,
            (byte >> 2) & 1,
            (byte >> 1) & 1,
            (byte) & 1)

def decompress(data):
    header = data[:4]
    if ord(header[0]) == 0x10:
        decompress_raw = decompress_raw_lzss10
    else:
        raise DecompressionError('Not an lzss-compressed file')

    decompressed_size, = unpack('<I', header[1:] + '\x00')
    return decompress_raw(data[4:], decompressed_size)

def decompress_raw_lzss10(indata, decompressed_size, _overlay=False):
    """Decompress LZSS-compressed bytes. Returns a bytearray."""
    data = bytearray()

    it = iter(indata)

    if _overlay:
        disp_extra = 3
    else:
        disp_extra = 1

    def writebyte(b):
        data.append(b)
    def readbyte():
        return ord(next(it))
    def readshort():
        # big-endian
        a = ord(next(it))
        b = ord(next(it))
        return (a << 8) | b
    def copybyte():
        data.append(next(it))

    while len(data) < decompressed_size:
        b = readbyte()
        flags = bits(b)
        for flag in flags:
            if flag == 0:
                copybyte()
            elif flag == 1:
                sh = readshort()
                count = (sh >> 0xc) + 3
                disp = (sh & 0xfff) + disp_extra

                for _ in range(count):
                    writebyte(data[-disp])
            else:
                raise ValueError(flag)

            if decompressed_size <= len(data):
                break

    if len(data) != decompressed_size:
        raise DecompressionError("decompressed size does not match the expected size")

    return data

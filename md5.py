import math
import sys
import argparse


def cr_Parser():
    _par = argparse.ArgumentParser()
    _par.add_argument('-i', '--input', type=argparse.FileType(mode='rb'))
    _par.add_argument('-o', '--output', type=argparse.FileType(mode='w'))
    return _par


def left_rotate(x, s):
    x &= 0xffffffff
    return ((x << s) | (x >> (32-s))) & 0xffffffff


def md5(mes):
    rotate_amounts = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]

    const = [int(abs(math.sin(i+1)) * 2**32) & 0xffffffff for i in range(64)]

    _abcd = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    _func = 16*[lambda x, y, z: (x & y) | (~x & z)] +\
        16*[lambda x, y, z: (z & x) | (~z & y)] +\
        16*[lambda x, y, z: x ^ y ^ z] +\
        16*[lambda x, y, z: y ^ (x | ~z)]
    _funcID = 16 * [lambda i: i] + \
        16 * [lambda i: (5 * i + 1) % 16] + \
        16 * [lambda i: (3 * i + 5) % 16] + \
        16 * [lambda i: (7 * i) % 16]
    mes = bytearray(mes)
    _bitLen = (8 * len(mes)) & 0xffffffffffffffff
    mes.append(0x80)
    while len(mes) % 64 != 56:
        mes.append(0)
    mes += _bitLen.to_bytes(8, byteorder='little')
    _hash = _abcd[:]

    for chunk_ofst in range(0, len(mes), 64):
        a, b, c, d = _hash
        chunk = mes[chunk_ofst:chunk_ofst+64]
        for i in range(64):
            f = _func[i](b, c, d)
            g = _funcID[i](i)
            rt = a + f + const[i] +\
                int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
            new_b = (b + left_rotate(rt, rotate_amounts[i])) & 0xffffffff
            a, b, c, d = d, new_b, b, c
        for i, val in enumerate([a, b, c, d]):
            _hash[i] += val
            _hash[i] &= 0xffffffff

    return sum(x*(0x100000000**i) for i, x in enumerate(_hash))


def _hexHash(_buf):
    tmp = _buf.to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(tmp, byteorder='big'))


def main():
    _par = cr_Parser()
    _arg = _par.parse_args(sys.argv[1:])

    final = _hexHash(md5(_arg.input.read()))
    _arg.output.write(final)
if __name__ == '__main__':
    main()

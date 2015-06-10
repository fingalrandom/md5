import sys
import argparse

def cr_Parser ():
    parser = argparse.ArgumentParser()
    parser.add_argument ('-i', '--input', type=argparse.FileType(mode='rb'))
    parser.add_argument ('-o', '--output', type=argparse.FileType(mode='w'))

    return parser


def left_rotate(x, s):
    x &= 0xffffffff

    return ((x<<s) | (x>>(32-s))) & 0xffffffff 
    
def ripemd160(mes):
    mes = bytearray(mes)
    orig_len_in_bits = (8 * len(mes)) & 0xffffffffffffffff
    mes.append(0x80)

    while len(mes)%64 != 56:
        mes.append(0)

    mes += orig_len_in_bits.to_bytes(8, byteorder='little')

    f = 16*[lambda x, y, z: x ^ y ^ z] + \
        16*[lambda x, y, z: (x & y) | (~x & z)] + \
        16*[lambda x, y, z: (x | ~y) ^ z] + \
        16*[lambda x, y, z: (x & z) | (y & ~z)] + \
        16*[lambda x, y, z: x ^ (y | ~z)]

    K = 16*[0x00000000] + \
        16*[0x5A827999] + \
        16*[0x6ED9EBA1] + \
        16*[0x8F1BBCDC] + \
        16*[0xA953FD4E]
    
    Kk = 16*[0x50A28BE6] + \
         16*[0x5C4DD124] + \
         16*[0x6D703EF3] + \
         16*[0x7A6D76E9] + \
         16*[0x00000000]

    r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
         3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
         1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
         4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]

    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    
    s = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
         11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
         11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
         9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]

    ss = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]

    init_abcde = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    hash_pieces = init_abcde[:]

    for chunk_ofst in range(0, len(mes), 64):
        a, b, c, d, e = hash_pieces
        aa, bb, cc, dd, ee = hash_pieces
        chunk = mes[chunk_ofst:chunk_ofst+64]

        for j in range(80):
            X = int.from_bytes(chunk[4*r[j]:4*r[j]+4], byteorder='little')
            T = (left_rotate(a + f[j](b, c, d) + X + K[j], s[j]) + e) & 0xffffffff
            a, e, d, c, b = e, d, left_rotate(c, 10), b, T
            Xx = int.from_bytes(chunk[4*rr[j]:4*rr[j]+4], byteorder='little')
            T = (left_rotate(aa + f[79-j](bb, cc, dd) + Xx + Kk[j], ss[j]) + ee) & 0xffffffff
            aa, ee, dd, cc, bb = ee, dd, left_rotate(cc, 10), bb, T
                        
        T = (hash_pieces[1] + c + dd) & 0xffffffff
        hash_pieces[1] = (hash_pieces[2] + d + ee) & 0xffffffff
        hash_pieces[2] = (hash_pieces[3] + e + aa) & 0xffffffff
        hash_pieces[3] = (hash_pieces[4] + a + bb) & 0xffffffff
        hash_pieces[4] = (hash_pieces[0] + b + cc) & 0xffffffff
        hash_pieces[0] = T

    return sum(x*(0x100000000**i) for i, x in enumerate(hash_pieces))

def _hexHash(bufferABCDE):
    tmp = bufferABCDE.to_bytes(20, byteorder='little')

    return '{:040x}'.format(int.from_bytes(tmp, byteorder='big'))

def main ():
    parser = cr_Parser()
    arguments = parser.parse_args(sys.argv[1:])

    final = _hexHash(ripemd160(arguments.input.read()))
    arguments.output.write(final)
 
if __name__=='__main__':
    main()

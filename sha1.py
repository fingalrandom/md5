import math
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

def sha1(mes):
    init_abcde = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]


    mes = bytearray(mes)
    orig_len_in_bits = (8 * len(mes)) & 0xffffffffffffffff

    if len(mes)%64 > 56:
        mes.append(0x80)
        while len(mes)%64 != 56:
            mes.append(0)
    else:
        mes.append(0x80)
        while len(mes)%64 != 56:
            mes.append(0)

    mes += orig_len_in_bits.to_bytes(8, byteorder='big')

    functions = 20*[lambda m, l, k: (m & l) | (~m & k)] + \
                20*[lambda m, l, k: m ^ l ^ k] + \
                20*[lambda m, l, k: (m & l) | (m & k) | (l & k)] + \
                20*[lambda m, l, k: m ^ l ^ k]

    K = 20*[0x5a827999] + \
        20*[0x6ed9eba1] + \
        20*[0x8f1bbcdc] + \
        20*[0xca62c1d6]

    hash_pieces = init_abcde[:]

    W = [[] for i in range(80)]

    for chunk_ofst in range(0, len(mes), 64):
        a, b, c, d, e = hash_pieces
        chunk = mes[chunk_ofst:chunk_ofst+64]
        for t in range(16):
            W[t] = int.from_bytes(chunk[4*t:4*t+4], byteorder='big')
                    
        for t in range(16,80):
            W[t] = left_rotate(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)

        for t in range(80):
            temp = (left_rotate(a, 5) + functions[t](b, c, d) + e + \
                    W[t] + K[t]) & 0xffffffff
            e, d, c, b, a = d, c, left_rotate(b, 30), a, temp

        for i,val in enumerate([a, b, c, d, e]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xffffffff

    return sum(x*(0x100000000**(4-i)) for i, x in enumerate(hash_pieces))

def _hexHash(bufferABCDE):
    tmp = bufferABCDE.to_bytes(20, byteorder='big')

    return '{:040x}'.format(int.from_bytes(tmp, byteorder='big'))

def main ():
    parser = cr_Parser()
    arguments = parser.parse_args(sys.argv[1:])

    final = _hexHash(sha1(arguments.input.read()))
    arguments.output.write(final)
 
if __name__=='__main__':
    main()

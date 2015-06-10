import sys
import argparse

def left_rotate(x, s):
    x &= 0xffffffff

    return ((x<<s) | (x>>(32-s))) & 0xffffffff 

def fun89(Ai,Ki):
    tmp = (Ai + Ki) & 0xffffffff
    out = []

    for i in range(8):
        out.append(tmp % 0x10)
        tmp = tmp >> 4
    #CryptoPro block    
    Ss = [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15,
         5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8,
         7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13,
         4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3,
         7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5,
         7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3,
         13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11,
         1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12]

    #Testing block
    S = [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3,
         14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9,
         5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11,
         7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3,
         6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2,
         4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14,
         13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12,
         1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
    
    unit = 0
    
    for i in range(8):
        out[i] = S[i*16 + out[i]]
            
    unit = sum(x*(0x10**i) for i,x in enumerate(out))
        
    unit = left_rotate(unit, 11)
    
    return unit #unit is integer! = 32 bits

def gost28147(block, Key):   #block = 64 bit, Key = 256 bit
    A = []
    B = []
    for i in range(33):
        A.append([])
        B.append([])

    B[0] = block >> 32
    A[0] = block & 0xffffffff
    
    K = []
    for i in range(8):
        K.append(Key & 0xffffffff)
        Key = Key >> 32
        
    for i in range(8,32):
        K.append([])
                
    for i in range(8, 24):
        K[i] = K[i % 8]
        
    for i in range(24, 32):
        K[i] = K[7 - (i % 8)]
            
    for i in range(32):
        A[i+1] = B[i] ^ fun89(A[i], K[i])
        B[i+1] = A[i]

    result = A[32] * (2**32) + B[32] #result is integer! = 64 bits

    return result

def A(Y):   #Y = 256 bit
    y = []

    for i in range(4):
        y.append(Y % 0x10000000000000000)
        Y = Y >> 64

    unit = 0
    unit = (y[0] ^ y[1])*(2**192) + y[3]*(2**128) + y[2]*(2**64) + y[1]

    return unit #unit = 256 bits

def P(Y):   #Y = 256 bits
    y = []
    yfi = []

    for i in range(32):
        y.append(Y % 0x100)
        Y = Y >> 8

    for i in range(32):
        yfi.append(y[(i % 4) * 8 + int(i / 4)])

    unit = 0
    unit = sum(x*(0x100**i) for i,x in enumerate(yfi))

    return unit #unit = 256 bits

def keygen(Hin, m): #Hin = 256 bits, m = 256 bits
    C = [0, 0, 0xff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00, 0]

    K = []
    for i in range(4):
        K.append([])
    
    U, V, W = 0, 0, 0
    U, V = Hin, m
    W = U ^ V
    K[0] = P(W)
    
    for j in range(1,4):
        U = A(U) ^ C[j]
        V = A(A(V))
        W = U ^ V
        K[j] = P(W)
   
    return K

def cipher(Hin, K): #Hin = 256 bit K = [K1, K2, K3, K4]
    chunk = []

    for i in range(4):
        chunk.append(Hin % 0x10000000000000000)
        Hin = Hin >> 64
        
    s = []
    for i in range(4):
        s.append([])

    for i in range(4):
        s[i] = gost28147(chunk[i], K[i])

    S = 0
    S = (s[3])*(2**192) + s[2]*(2**128) + s[1]*(2**64) + s[0]
    
    return S # S = 256 bits

def psi(Y):   #Y = 256 bits
    y = []
    tmp = []
    
    for i in range(16):
        y.append(Y % 0x10000)
        Y = Y >> 16
        tmp.append([])
    
    tmp[0] = y[0] ^ y[1] ^ y[2] ^ y[3] ^ y[12] ^ y[15]

    for i in range(1,16):
        tmp[i] = y[16 - i]
                
    unit = 0
    unit = sum(x*(0x10000**(15-i)) for i,x in enumerate(tmp))

    return unit #unit = 256 bits

def mix(Hin, S, m): #all = 256 bits
    
    for i in range(12):
        S = psi(S)

    Hout = psi(Hin ^ psi(m ^ S))
    
    for i in range(60):
        Hout = psi(Hout)

    return Hout

def f_step(Hin, m):
    key = keygen(Hin, m)
    do_cipher = cipher(Hin, key)
    result = mix(Hin, do_cipher, m)

    return result

def gost3411(message): #message = bytes
    modul = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    shift = 0x10000000000000000000000000000000000000000000000000000000000000000
    
    message = bytearray(message)

    len_in_bits = (8 * len(message)) & modul

    m = []
    num_of_step = 0
    num_of_nul = 0
    control_sum = 0 
    h = 0
    
    if len(message) % 32 == 0:
        num_of_step = len(message) // 32
    else:
        num_of_step = (len(message) // 32) + 1
        num_of_nul = 32 - (len(message) % 32)

    for i in range(0, (num_of_step - 1)*32, 32):
        m.append(message[i:i+32])
        
    m.append(message[(num_of_step-1)*32:len(message)])

    for i in range(num_of_nul):
        m[num_of_step - 1].append(0)

    for i in range(num_of_step):
        h = f_step(h, int.from_bytes(m[i], 'little'))
    
    h = f_step(h, len_in_bits)

    for i in range(num_of_step):
        control_sum += int.from_bytes(m[i], 'little')

    h = f_step(h, control_sum)

    return h

def _hexHash(buffer):
    tmp = buffer.to_bytes(32, 'little')

    return '{:064x}'.format(int.from_bytes(tmp, 'big'))

def main ():
    msg = b'message digest'
    final = _hexHash(gost3411(msg))
    print(final)
 
if __name__=='__main__':
    main()

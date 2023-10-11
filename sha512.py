# This is a list of values that are used to determine the hash algorithm. 
HASH_VALUES = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
]

# Returns a list of round constant terms.
ROUND_CONSTANTS = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

def Ch(e, f, g):
    """
     Returns the Ch function. 
     This function is used to determine whether or not a pair of bit masks 
     are set and if so whether or not they are set.
    """
    return (e & f) ^ (~e & g)

def Maj(a, b, c):

    #Returns Maj of a b and c. 

    return (a & b) ^ (a & c) ^ (b & c)

def rotr(x, n):

     #Right shift a 64 - bit integer. 
    return (x >> n) | (x << (64 - n))

def summation_a(a):

    #Summation of A.
    return rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)

def summation_e(e):
    #Summation of E - bit values.     
    return rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)

def sigma_0(word):
    """
     Implements the Sigma_0 function. It is used to encrypt / decrypt a word of 0's and 1's
     
     @param word - The word to be encrypted / decrypted
     
     @return The encrypted / decrypted word of 0's and 1's as a 64 - bit unsigned integer
    """
    return rotr(word, 1) ^ rotr(word, 8) ^ (word >> 7)

def sigma_1(word):
     #The Sigma - 1 function is used to encrypt or decrypt a word. 
    return rotr(word, 19) ^ rotr(word, 61) ^ (word >> 6)

def addition_modulo_2_64(value):
    
     #This function is used to add 2^64 to a value
    return value % (2 ** 64)

def pad_message(message):
    
    #Pad a message with padding. 
    message += b"\x80"  # Adding 1 byte (10000000)
    
    # This is a little bit of the message.
    while len(message) % 128 != 112:
        message += b"\x00"
    message += (len(message) * 8).to_bytes(16, "big")
    return message

def divide_to_blocks(message):
    blocks = [message[i:i + 128] for i in range(0, len(message), 128)]
    return blocks

def sha512(message):
   
    hash_values = HASH_VALUES.copy()

    blocks = divide_to_blocks(pad_message(message))

    # This function is used to compress the block values.
    for block in blocks:
        compression_function(hash_values, block)

    return "".join(format(h, "016x") for h in hash_values)

def compression_function(hash_values, message):
    a, b, c, d, e, f, g, h = hash_values
    W = [0] * 80

    # Decode the message as an integer.
    for t in range(16):
        W[t] = int.from_bytes(message[t * 8:(t + 1) * 8], byteorder="big")

    for t in range(16, 80):
        W[t] = sigma_1(W[t - 2] + W[t - 7]) + sigma_0(W[t - 15] + W[t - 16])

    # Return the summation of the two decimal places.
    for t in range(80):
        T1 = h + (Ch(e, f, g) + summation_e(e) + ROUND_CONSTANTS[t] + W[t])
        T2 = summation_a(a) + Maj(a, b, c)
        h = g
        g = f
        f = e
        e = addition_modulo_2_64(d + T1)
        d = c
        c = b
        b = a
        a = addition_modulo_2_64(T1 + T2)


    hash_values[0] = addition_modulo_2_64(hash_values[0] + a)
    hash_values[1] = addition_modulo_2_64(hash_values[1] + b)
    hash_values[2] = addition_modulo_2_64(hash_values[2] + c)
    hash_values[3] = addition_modulo_2_64(hash_values[3] + d)
    hash_values[4] = addition_modulo_2_64(hash_values[4] + e)
    hash_values[5] = addition_modulo_2_64(hash_values[5] + f)
    hash_values[6] = addition_modulo_2_64(hash_values[6] + g)
    hash_values[7] = addition_modulo_2_64(hash_values[7] + h)

# This function is called from the main module
if __name__ == "__main__":
    message = input("Enter a message: ").encode("utf-8")
    result = sha512(message)
    print("SHA-512 Hash:", result)
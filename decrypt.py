import secrets
import random
import sys
from Cryptodome.Cipher import AES
from Cryptodome import Random
#import hybrid
import stego
import numpy as np
from PIL import Image
import ast
np.set_printoptions(threshold=sys.maxsize)

def decryptAES(cipherAESd,cipherText):
    dec= cipherAESd.decrypt(cipherText)
    return dec

def decrypt(pk, ciphertext):
    d, n = pk
    m = [chr((char ** d) % n) for char in ciphertext]
    return m

def Decode(src):
    img = Image.open(src, 'r')
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4

    total_pixels = array.size//n

    hidden_bits = ""
    for p in range(total_pixels):
        for q in range(0, 3):
            hidden_bits += (bin(array[p][q])[2:][-1])

    hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]

    message = ""
    for i in range(len(hidden_bits)):
        if message[-5:] == "PR0J3":
            break
        else:
            message += chr(int(hidden_bits[i], 2))
    if "PR0J3" in message:
        print("Hidden Message:", message[:-5])
        return message[:-5]
    else:
        print("No Hidden Message Found")

def main(src):
    message = Decode(src)
    cipherText = ast.literal_eval(message)
    pri = tuple(int(item) for item in input("Enter the Private Key: ").split(','))
    cipherKey=[int(item) for item in input("Enter the AES Symmetric Key: ").split(',')]
    nonce1 = input("Enter nonce value: ")
    nonce=ast.literal_eval(nonce1)

    decryptedKey = ''.join(decrypt(pri,cipherKey))
    print("\nDecrypting the AES Symmetric Key...")

    decryptedKey = decryptedKey.encode('utf-8')
    cipherAESd = AES.new(decryptedKey, AES.MODE_GCM, nonce=nonce)
    decrypted = decryptAES(cipherAESd,cipherText)
    print("\nDecrypting the message using the AES symmetric key.....")
    print("Decrypted message: ", decrypted)

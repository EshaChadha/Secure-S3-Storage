import euclid
import mail
from configparser import ConfigParser
import secrets
from Cryptodome.Cipher import AES
from Cryptodome import Random
import stego

def mainMenu(src):
    print("\n******************************************************************")
    print("******************************************************************")
    print("\t\t\tWelcome!!")
    print("\t\tSecure S3 Data Storage")
    print("\tThis tool will encrypt a message using AES and RSA")
    print("******************************************************************")
    print("******************************************************************\n")


    print("\nGenerating RSA Public and Privite keys......")
    pub,pri=euclid.KeyGeneration()
    print("Generated RSA Keys")


    print("\nGenerating AES symmetric key......")
    key = secrets.token_hex(16)
    KeyAES=key.encode('utf-8')
    print("Generated AES Key")

    # The message gets encrypted using the AES key which was generated above
    plainText = input("\nEnter the message: ")
    cipherAESe = AES.new(KeyAES,AES.MODE_GCM)
    nonce = cipherAESe.nonce

    print("\nEncrypting the message with AES......")
    cipherText=euclid.encryptAES(cipherAESe,plainText)
    stego.Encode(src, cipherText, src)

    print("\nSuccessfully encrypted the message and the cipher text is hidden in the picture......")

    # Encrypt the symmetric key using public key.
    print("\nEncrypting the AES symmetric key with RSA Public key......")
    cipherKey=euclid.encrypt(pub,key)
    print("Encrypted the AES key")

    # sending mail
    mail.mail(pri, cipherKey, nonce, src)

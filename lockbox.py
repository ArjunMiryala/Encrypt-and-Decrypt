from cryptography.hazmat.primitives.kdf.scrypt import Scrypt # scrypt module imported, kdf.scrypt gives us the Scrypt key derivation function (KDF).
from pathlib import Path  ## to work with file paths easily
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # # AESGCM is a class from the cryptography library for encryption 
import os, secrets # # for generating secure random bytes # Designed for cryptography
import sys
import argparse
import getpass



MAGIC = b"LB1" # 3-byte identifier for "lockbox v1" ## This helps us recognize our own encrypted files later. #This helps later in decrypt() to check: “is this a file I encrypted?”
SALT_LEN = 16  # 128-bit salt  ## Salt is 128 bits = 16 bytes. Long enough to be unique.
NONCE_LEN = 12 # 96-bit(12 bytes) nonce(standrd for AES-GCM)


def derive_key(password: bytes, salt: bytes) -> bytes: #the password must be converted to bytes (not string). converting salt to bytes.#salt: bytes → a random value added to the password to make each key unique.
    # -> bytes  this function returns a binary key, not a string.
    kdf = Scrypt( #KDF = turns a password + salt into a binary key. 
        salt=salt, ## required randomness to prevent rainbow attacks
        length=32,  # 256-bit & AES key #AES‑GCM needs a raw binary key: 32 bytes for AES‑256 We can't use strings directly they're guessable & not binary
        n=2**15, # work factor (higher = slower = safer),CPU + memory cost. n = 32768 makes brute-force much slower.
        r=8,    # Controls memory usage (block size). 8 is default for good balance.
        p=1 # parallelization( 1 thread is fine) 1 means run on one core (simple & safe).
    )
    
    return kdf.derive(password) #This runs the password + salt through scrypt # returns binary string aka my final AES256 key

def encrypt(path: Path,password: str) -> None: #path = the file you want to encrypt #password = the master password to lock it
   # Path is from pathlib and makes file handling cross-platform and safer than using plain strings.
   #encrypt(Path("family.jpg"), "Arjun")
    data = path.read_bytes() #read the file contents #This loads the entire file into memory as binary (bytes) ,,,use read_bytes() because it works even for images, PDFs, zip files
    salt = secrets.token_bytes(SALT_LEN) # generating random salt of 16bytes, salt is not secret but it should be random and unique per file. salt is saved in outputfile, for getting key during decryption
    nonce = secrets.token_bytes(NONCE_LEN)# Generate a random nonce (IV) #it is "number used once", for ARS-GCM must be unique per encryption, 12 bytes is standard& required by ARSGCM class & It also helps generate the authentication tag
    KEY = derive_key(password.encode(), salt) #password.encode() converts "hello123" into b"hello123" (bytes required)#So this line gives you a secure 256-bit binary key based on the user's password and the random salt
    #I already wrote derive_key()
    aesgcm = AESGCM(key) #We give it the key and use .encrypt()
    ciphertext = aesgcm.encrypt(nonce, data, None)  # #associated_data is optional so I give None here because Iam not attaching anything extra. # # result is ciphertext with authentication tag

    out_path = path.with_suffix(path.suffix + ".pv") #path.with_suffix(...) to creates a new file with .pv (photo vault) extension Example: hello.jpg to hello.jpg.pv #and also <path.suffix +".pv"> inlcudes the .(period) in .pv
    out_path.write_bytes(MAGIC + salt + nonce + ciphertext) #This way, the decrypt function will later: #check MAGIC, read salt to derive key, read nonce, decrypt ciphertext

def decrypt(path: Path, password: str) -> None: #path: the .pv file (e.g. family.jpg.pv) #using the same passwor which was used to encrypt 
    blob = path.read_bytes()  # read all the encripted file(.pv) data(magic,salt,nonce,ciphertext)
    if blob[:3] != MAGIC: # checking for the correct magic bytes #blob[:3] gets the first 3 bytes #If it’s not b"LB1", this file wasn’t created by my encrypt tool or someone tampered with it
        sys.exit("Not a lockbox file (magic bytes mismatch).")  #stops the program with an error message, This is how we avoid corrupt or unsupported files.
        
    # These values must be exactly the same length used in encryption
    salt = blob[3 : 3 + SALT_LEN] #salt starts at byte3 and ends at byte19
    nonce = blob[3 + SALT_LEN : 3 + SALT_LEN + NONCE_LEN] # nonce staers at byte19 and ends at byte31
    ciphertext = blob[3 + SALT_LEN + NONCE_LEN :] # the cyphertext is from byte31 to end of the file

    key = derive_key(password.encode(), salt) #Just like encrypt must use the same salt + same password to get the same key Otherwise, decryption will fail (which is what we want for security)
    aesgcm = AESGCM(key) #AESGCM is initialized with the same key
    data = aesgcm.decrypt(nonce, ciphertext, None)  #.decrypt() will return the original file content-only if everything is valid # if the password is wrong or file tampered iw will rasie an exception
 
    out_path = path.with_suffix("") # with_suffix("") strips off .pv example: family.jpg.pv to family.jpg 
    out_path.write_bytes(data) # we now have the original file
    
    print(f"Decrypted: {path.name} to {out_path.name}")

    path.unlink() # deleted the .pv file after successfull decryption


def main() -> None:
    parser = argparse.ArgumentParser(description="lockbox - encrypt & decrypt fils securly") #description=... is shown when someone runs python lockbox.py --help #Creates the top-level parser that handles command-line arguments
    sub = parser.add_subparsers(dest="command", required= True) #Adds subcommands like encrypt and decrypt #dest="command" means: store the subcommand name (e.g., "encrypt") in args.command
    #required=True: the user must specify one of the subcommands, or it’ll show a help message
 
    encrypt_parser = sub.add_parser("encrypt", help="Encrypt a file") #Adds a subcommand called encrypt 
    encrypt_parser.add_argument("file", type=Path) #type=Path means the argument will be converted into a Path object from pathlib #Requires 1 positional argument: the path to the file you want to encrypt


    decrypt_parser = sub.add_parser("decrypt", help="Decrypt a .pv file") #Adds a subcommand called decrypt
    decrypt_parser.add_argument("file", type=Path) #same as encypt expects a 1 positional argument(in this case encrypted .pv file)

    args = parser.parse_args() #parses the arguments from the commandline and puts them in args object
    # we can now access args.command(to "encrypt" or "decrypt") , args.file (a path object for the file)

    password = getpass.getpass("Master password: ") # Asks the user to type  a password withput showing it on screen
    # this is uses built-in getpass module #then the password is passed to encrypt() or decrypt()

    try: # This block decides which function to run
        if args.command =="encrypt":
            encrypt(args.file, password)          #It checks if the subcommand was "encrypt" or "decrypt"
        elif args.command == "decrypt":           #Then calls the corresponding function with the file path and password
            decrypt(args.file, password)          
    except Exception as e: #If any error happens (bad password, file not found, etc.), Exception catches it and exits cleanly(sys.exit()) #Exception is base class for all normal python errors
        sys.exit(f"error: {e}") # shows the error messages # here e is the error #try lets us catch those issues and show the user a nice message.

    

if __name__ == "__main__":  #python convention # checks if the file is being run directly(python lockbox.py) then it calls main() and runs CLI
    main()
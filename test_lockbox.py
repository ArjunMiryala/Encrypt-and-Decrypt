import os  # used for cleanup
from pathlib import Path 
from lockbox import encrypt, decrypt # importing required functions from the main py file

def test_round_trip():
    password = "I love Tempe" #A hardcoded password we’ll use for both encryption and decryption(okay for testing but not real apps)
    original_text = b"I love sweets from India" #fake test data#b"" converts the short string  to bytes# storing data in bytes #to write this into a file and try to encrypt/decrypt it

    #These variables define the full test cycle: before, during, after. (These are just variables, not file creation commands.)
    original_path = Path("test_file.txt") # create this to encrypt and decrypt #does not create the file. It just gives you a reference to that file if/when it exists.
    encrypted_path = Path("test_file.txt.pv") # this will be created by the encrypt() function
    decrypted_path = Path("test_file.txt") # this is the file restored by the decrypt() function.It has the same name cause it removes the .pv


    original_path.write_bytes(original_text) # It creates a new file test_file.txt, writes the test string into it 
    #we now have a real file on disk that simulates  "family photo" or secret doc in our main project

    encrypt(original_path, password)  #calls our encrypt() function using test file and password # we get .pv file(the encrypted output). # just using a Path(original_path) object instead of a raw string.
    
    if not encrypted_path.exists(): #checking if the encryption failed 
        raise FileNotFoundError("Encryption failed: .pv file has not been created ")
    
    original_path.unlink() #Deletes the original encrypted file from the disk (real world scenario)
    #To make sure we are  decrypting only from ciphertext, not accidentally comparing the same file twice


    decrypt(encrypted_path, password) #Calls our decrypt() function now using the .pv file and same password #It re-creates test_file.txt with decrypted contents
    # This step must succeed if the key, nonce, and ciphertext are all correct

    if not decrypted_path.exists():
        raise FileNotFoundError("Decryption failed: Output file not created")

    decrypted_text = decrypted_path.read_bytes() #Loads the newly created file back into memory #his is the decrypted version of our test string

  
    assert decrypted_text == original_text, "Decrypted output does not match the input"  # compare the original and decrypted content
    # if not same, python will raise Assertion error # this ensures our test roundtrip is lossless and correct

    print("round trip test passed") # we only reach this line when everyhting goes correct
    if encrypted_path.exists():
        encrypted_path.unlink() #deletes the .pv file 
    if decrypted_path.exists():
        decrypted_path.unlink()# cleans up the folder after testing,deletes decrypted.txt file.


if __name__ == "__main__":
    test_round_trip()


import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Prompt the user for whether they want to encrypt or decrypt
mode = input("Would you like to (E)ncrypt or (D)ecrypt? ")

if mode.lower() == "e":
    # Encrypt the data
    # Prompt the user for the password and data to encrypt
    password = input("Enter the password: ")
    data = input("Enter the data to encrypt: ")

    # Derive a key from the password using PBKDF2
    salt = b'salt_'  # salt can be any bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Use the key to encrypt the data with Fernet
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())

    # Encode the encrypted data in base64 and print it
    print("Encrypted data:", base64.b64encode(encrypted_data).decode())
    input('Press enter to exit')

elif mode.lower() == "d":
    try:
        # Decrypt the data
        # Prompt the user for the password and data to decrypt
        password = input("Enter the password: ")
        data = input("Enter the data to decrypt: ")

        # Derive the key from the password using PBKDF2
        salt = b'salt_'  # salt can be any bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Decode the base64-encoded data
        decoded_data = base64.b64decode(data)

        # Use the key to decrypt the data with Fernet
        f = Fernet(key)
        decrypted_data = f.decrypt(decoded_data).decode()

        # Print the decrypted data
        print("Decrypted data:", decrypted_data)
        input('Press enter to exit')
    except:
        print("Invalid password or data.")
        input('Press enter to exit')

else:
    print("Invalid mode. Please enter E or D.")
    input('Press enter to exit')

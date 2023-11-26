import cv2
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return ciphertext, cipher.nonce, tag

def decrypt_message(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_msg = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return decrypted_msg
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return None

def main():
    img = cv2.imread("banner1.png")

    # Encrypt
    msg = input("Enter secret message:\t")
    password = input("Enter a passcode:\t")

    key = get_random_bytes(16)  # Generating a secure random key
    encrypted_msg, nonce, tag = encrypt_message(msg, key)

    n, m, z = 0, 0, 0
    for i in range(len(encrypted_msg)):
        img[n, m, z] = encrypted_msg[i]
        n = n + 1
        m = m + 1
        z = (z + 1) % 3

    cv2.imwrite("EncryptedImg.png", img)
    os.startfile("EncryptedImg.png")
    print("Image encrypted and saved.")

    # Decrypt
    entered_password = input("Enter passcode for Decryption:\t")
    if password == entered_password:
        decrypted_msg = decrypt_message(encrypted_msg, key, nonce, tag)
        if decrypted_msg:
            print("Decrypted message:\t", decrypted_msg)
    else:
        print("You are not authorized")

if __name__ == "__main__":
    main()

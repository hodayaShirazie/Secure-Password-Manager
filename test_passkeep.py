import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import string
import random
import datetime

# Functions matching the main class logic

def pad_key(key):
    """Pad the key to a multiple of 16 bytes (as in the main code)."""
    return key + ("0" * (16 - len(key) % 16)) if len(key) % 16 != 0 else key

def encrypt_password(key, password):
    """Encrypt a password using AES (CBC mode)."""
    aes = AES.new(key.encode(), AES.MODE_CBC, key[:16].encode())
    enc_pwd = aes.encrypt(pad(password.encode(), AES.block_size))
    return base64.b64encode(enc_pwd).decode()

def decrypt_password(key, enc_pwd_b64):
    """Decrypt a base64-encoded encrypted password."""
    enc_pwd = base64.b64decode(enc_pwd_b64)
    aes = AES.new(key.encode(), AES.MODE_CBC, key[:16].encode())
    return unpad(aes.decrypt(enc_pwd), AES.block_size).decode()

def generate_password(length=32):
    """Generate a strong random password (as in the GUI)."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(chars, k=length))

def backup_filename():
    """Generate a backup filename as in backup_db_gui."""
    return f"passwords_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"

class TestPassKeepLogic(unittest.TestCase):
    def test_pad_key(self):
        # Check that the padded key is always a multiple of 16
        key = '12345'
        padded = pad_key(key)
        self.assertEqual(len(padded) % 16, 0)
        self.assertTrue(padded.startswith(key))
        print('test_pad_key: PASSED')

    def test_encrypt_decrypt(self):
        # Check that encryption and decryption work as expected
        key = pad_key('testkey12345')
        password = 'MySecretPassword!'
        enc = encrypt_password(key, password)
        dec = decrypt_password(key, enc)
        self.assertEqual(password, dec)
        print('test_encrypt_decrypt: PASSED')

    def test_wrong_key_fails(self):
        # Check that decryption with a wrong key fails
        key = pad_key('testkey12345')
        wrong_key = pad_key('otherkey54321')
        password = 'AnotherSecret!'
        enc = encrypt_password(key, password)
        with self.assertRaises(Exception):
            decrypt_password(wrong_key, enc)
        print('test_wrong_key_fails: PASSED')

    def test_generate_password(self):
        # Test the password generation function
        pwd = generate_password()
        self.assertEqual(len(pwd), 32)
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in string.punctuation for c in pwd))
        print('test_generate_password: PASSED')

    def test_backup_filename_format(self):
        # Test the format of the backup filename
        name = backup_filename()
        self.assertTrue(name.startswith('passwords_backup_'))
        self.assertTrue(name.endswith('.db'))
        # Check date/time format in the filename
        date_part = name[len('passwords_backup_'):-3]
        self.assertEqual(len(date_part), 15)  # YYYYMMDD_HHMMSS
        print('test_backup_filename_format: PASSED')

if __name__ == '__main__':
    unittest.main()

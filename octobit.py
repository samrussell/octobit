import argparse
from getpass import getpass
from pylibscrypt import scrypt
from Crypto.Cipher import AES
import struct
from protobuf.wallet_pb2 import Wallet

# taken from read-multibit-wallet-file
DEFAULT_N = 16384 # 2^14
DEFAULT_R = 8
DEFAULT_P = 1
DEFAULT_DERIVED_KEY_LENGTH = 32
DEFAULT_SALT = struct.pack("BBBBBBBB", 0x35, 0x51, 0x03, 0x80, 0x75, 0xa3, 0xb0, 0xc5)
FIXED_IV = struct.pack("BBBBBBBBBBBBBBBB",
  0xa3, 0x44, 0x39, 0x1f, 0x53, 0x83, 0x11, 0xb3,
  0x29, 0x54, 0x86, 0x16, 0xc4, 0x89, 0x72, 0x3e
  )

AES_BLOCK_LENGTH = 16

def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('filename', help="path to multibit HD wallet file")
  return parser.parse_args()

def decrypt(key, iv, encrypted_data):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return cipher.decrypt(encrypted_data)

def decrypt_padded_aes(key, iv, crypted_data):
  decrypted_message = decrypt(key, iv, crypted_data)
  # PKCS#7 padding
  number_of_blocks = len(decrypted_message) / AES_BLOCK_LENGTH
  last_block = decrypted_message[(number_of_blocks - 1)*AES_BLOCK_LENGTH:]
  # check last byte
  padding_length = ord(last_block[-1])
  if padding_length > AES_BLOCK_LENGTH:
    raise Exception("Bad crypted data - padding value doesn't make sense")
  padding_bytes = last_block[0-padding_length:]
  if chr(padding_length) * padding_length != padding_bytes:
    raise Exception("Bad crypted data - padding bytes aren't all equal")
  # we're good, remove them
  return decrypted_message[:0-padding_length]

def load_crypted_wallet(filename, scrypt_key):
  with open(filename, "rb") as file:
    data = file.read()
    return decrypt_padded_aes(scrypt_key, data[:16], data[16:])

def build_wallet(serialised_wallet):
  wallet = Wallet()
  wallet.ParseFromString(serialised_wallet)

  return wallet

def build_scrypt_key(passphrase, salt):
  coded_passphrase = struct.pack(">" + "H" * len(passphrase), *[ord(x) for x in passphrase])
  return scrypt(coded_passphrase, salt, N=DEFAULT_N, r=DEFAULT_R, p=DEFAULT_P, olen=DEFAULT_DERIVED_KEY_LENGTH)

def export_key(filename, passphrase):
  wallet_key = build_scrypt_key(passphrase, salt=DEFAULT_SALT)
  serialised_wallet = load_crypted_wallet(filename, wallet_key)
  wallet = build_wallet(serialised_wallet)

  key_object = wallet.key[0]

  # we assume here that type = DETERMINISTIC_MNEMONIC, this might not always be true

  key_key = build_scrypt_key(passphrase, salt=wallet.encryption_parameters.salt)
  decrypted_key = decrypt_padded_aes(key_key, key_object.encrypted_data.initialisation_vector, key_object.encrypted_data.encrypted_private_key)

  return "".join(decrypted_key)

def run():
  args = get_args()
  passphrase = getpass("Enter your passphrase: ")
  print(export_key(args.filename, passphrase))

if __name__ == "__main__":
  run()
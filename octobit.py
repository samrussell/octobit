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

def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('filename', help="path to multibit HD wallet file")
  return parser.parse_args()

def decrypt(key, iv, encrypted_data):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return cipher.decrypt(encrypted_data)

def load_crypted_wallet(filename, passphrase):
  coded_passphrase = struct.pack(">" + "H" * len(passphrase), *[ord(x) for x in passphrase])
  scrypt_key = scrypt(coded_passphrase, DEFAULT_SALT, N=DEFAULT_N, r=DEFAULT_R, p=DEFAULT_P, olen=DEFAULT_DERIVED_KEY_LENGTH)
  with open(filename) as file:
    data = file.read()
    serialised_wallet = decrypt(scrypt_key, data[:16], data[16:])
  wallet = Wallet()
  wallet.ParseFromString(serialised_wallet)
  
  return wallet

def export_keys(filename, passphrase):
  wallet = load_crypted_wallet(filename, passphrase)

def run():
  args = get_args()
  passphrase = getpass("Enter your passphrase: ")
  export_keys(args.filename, passphrase)

if __name__ == "__main__":
  run()
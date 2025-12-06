import argparse
import base64
import json
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad


def load_private_key(path: Path) -> RSA.RsaKey:
    if not path.exists():
        raise FileNotFoundError(f"Missing private key at {path}")
    return RSA.import_key(path.read_bytes())


def decode_field(payload: dict, key: str) -> bytes:
    if key not in payload:
        raise KeyError(f"Payload missing field '{key}'")
    return base64.b64decode(payload[key])


def verify_mac(mac_key: bytes, iv: bytes, ciphertext: bytes, encrypted_key: bytes, mac_value: bytes) -> None:
    # Recompute HMAC over the transmitted fields; raises if invalid
    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(iv)
    mac.update(ciphertext)
    mac.update(encrypted_key)
    mac.verify(mac_value)


def decrypt_message(private_key: RSA.RsaKey, payload: dict) -> bytes:
    encrypted_master = decode_field(payload, "encrypted_key")
    iv = decode_field(payload, "iv")
    ciphertext = decode_field(payload, "ciphertext")
    mac_value = decode_field(payload, "mac")

    rsa_cipher = PKCS1_OAEP.new(private_key)
    master_key = rsa_cipher.decrypt(encrypted_master)
    aes_key, mac_key = master_key[:16], master_key[16:]

    # Stop if MAC fails before attempting decryption
    verify_mac(mac_key, iv, ciphertext, encrypted_master, mac_value)

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = aes_cipher.decrypt(ciphertext)
    return unpad(plaintext_padded, AES.block_size)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate receiver: verify MAC, decrypt AES key, and recover plaintext.")
    parser.add_argument("-i", "--input", type=Path, default=Path("Transmitted_Data.json"), help="Path to transmitted payload.")
    parser.add_argument("-s", "--self", dest="identity", default="bob", help="Your identity used to load <name>_private.pem.")
    parser.add_argument("-o", "--out", type=Path, default=Path("decrypted_message.txt"), help="Where to write the recovered plaintext.")
    args = parser.parse_args()

    payload = json.loads(args.input.read_text())
    private_key_path = Path(f"{args.identity}_private.pem")
    private_key = load_private_key(private_key_path)

    plaintext = decrypt_message(private_key, payload)
    args.out.write_bytes(plaintext)
    print(f"Decrypted message written to {args.out}")


if __name__ == "__main__":
    main()

import argparse
import base64
import json
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def load_public_key(path: Path) -> RSA.RsaKey:
    if not path.exists():
        raise FileNotFoundError(f"Missing public key at {path}")
    return RSA.import_key(path.read_bytes())


def generate_session_keys() -> tuple[bytes, bytes, bytes]:
    # 32 random bytes split into an AES key and an HMAC key
    master_key = get_random_bytes(32)
    return master_key, master_key[:16], master_key[16:]


def encrypt_message(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    # Fresh IV each run; CBC with PKCS7 padding
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext


def compute_mac(mac_key: bytes, iv: bytes, ciphertext: bytes, encrypted_key: bytes) -> bytes:
    # HMAC over all transmitted binary fields to detect tampering
    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(iv)
    mac.update(ciphertext)
    mac.update(encrypted_key)
    return mac.digest()


def write_transmission(out_path: Path, payload: dict) -> None:
    out_path.write_text(json.dumps(payload, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate sender: encrypt message with AES and wrap key with RSA.")
    parser.add_argument("-m", "--message", type=Path, default=Path("message.txt"), help="Path to plaintext message file.")
    parser.add_argument("-r", "--receiver", default="bob", help="Receiver name used to load <name>_public.pem.")
    parser.add_argument("-o", "--out", type=Path, default=Path("Transmitted_Data.json"), help="Output file to write transmitted payload.")
    args = parser.parse_args()

    plaintext_path: Path = args.message
    receiver_pub_path = Path(f"{args.receiver}_public.pem")

    plaintext = plaintext_path.read_bytes()
    receiver_key = load_public_key(receiver_pub_path)

    master_key, aes_key, mac_key = generate_session_keys()

    iv, ciphertext = encrypt_message(plaintext, aes_key)

    rsa_cipher = PKCS1_OAEP.new(receiver_key)
    encrypted_master = rsa_cipher.encrypt(master_key)

    mac = compute_mac(mac_key, iv, ciphertext, encrypted_master)

    payload = {
        "receiver": args.receiver,
        "scheme": "AES-128-CBC + HMAC-SHA256 + RSA-OAEP",
        "encrypted_key": base64.b64encode(encrypted_master).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "mac": base64.b64encode(mac).decode("ascii"),
    }

    write_transmission(args.out, payload)
    print(f"Transmitted data written to {args.out}")


if __name__ == "__main__":
    main()

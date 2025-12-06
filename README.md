# Secure Messaging Simulation

Two scripts simulate a sender and receiver exchanging an encrypted file using the shared RSA keys already in the repo (`alice_private/public.pem`, `bob_private/public.pem`). Do **not** re-run `key_generator.py` or the keys will be replaced and decryption will break across teammates.

## Files
- `sender.py` — reads a plaintext file, encrypts it with AES-128-CBC, wraps the session key with the receiver's RSA public key (OAEP), authenticates with HMAC-SHA256, and writes `Transmitted_Data.json`.
- `receiver.py` — reads `Transmitted_Data.json`, uses the receiver's RSA private key to unwrap the session key, verifies the MAC, decrypts the message, and writes the plaintext.
- `key_generator.py` — existing script that would regenerate all key files (avoid running).

## Sender usage
```bash
python sender.py -m message.txt -r bob -o Transmitted_Data.json
```
- `-m/--message` path to plaintext file.
- `-r/--receiver` picks which `*_public.pem` to use (default `bob`).
- `-o/--out` output payload file (default `Transmitted_Data.json`).

## Receiver usage
```bash
python receiver.py -i Transmitted_Data.json -s bob -o decrypted_message.txt
```
- `-i/--input` payload file from sender.
- `-s/--self` selects your private key (`*_private.pem`); default `bob`.
- `-o/--out` plaintext output file.

## Protocol summary
- Session master key: 32 random bytes split into AES key (first 16) and HMAC key (last 16).
- Encryption: AES-128-CBC with PKCS7 padding; IV is random and stored in the payload.
- Integrity: HMAC-SHA256 over IV, ciphertext, and the RSA-encrypted master key.
- Key wrapping: RSA 2048 with OAEP using the receiver's public key.

## Workflow example
1. Place your message in `message.txt`.
2. Run the sender targeting the receiver (e.g., `python sender.py -r bob`).
3. Share `Transmitted_Data.json` with the receiver.
4. Receiver runs `python receiver.py -s bob` to verify, decrypt, and recover `decrypted_message.txt`.

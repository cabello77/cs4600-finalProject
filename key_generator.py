from Crypto.PublicKey import RSA

# Function to generate and save keys
def make_keys(name):
    key = RSA.generate(2048)  # Generate private key (includes public key)
    # Save private key
    with open(f"{name}_private.pem", "wb") as f:
        f.write(key.export_key())
    # Save public key
    with open(f"{name}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print(f"Created keys for {name}")

# Generate keys for both parties
make_keys("alice")
make_keys("bob")

print("Done generating keys.")


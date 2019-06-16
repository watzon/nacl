# NaCl

Full Crystal binidings to [libsodium](https://libsodium.org). Very much a work in progress, but the lib bindings are there.

## Installation

1. Make sure you have `libsodium` installed on your system.

```bash
# Debian
sudo apt install libsodium23

# Arch
sudo pacman -S libsodium

# Fedora
sudo yum install libsodium
```

2. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     nacl:
       github: watzon/nacl
   ```

2. Run `shards install`

## Usage

```crystal
require "nacl"
```

#### Secret Key Encryption

##### XChaCha20Poly1305

```crystal
# Generate a random secret key
key = NaCl::AEAD::XChaCha20Poly1305.keygen

# Initialize a XChaCha20Poly1305 cipher object
cipher = NaCl::AEAD::XChaCha20Poly1305.new(key)

# Generate a random nonce: a single-use value never repeated under the same key.
# The nonce isn't secret, and can be sent with the ciphertext.
# The cipher instance has a nonce_bytes method for determining how many bytes should be in a nonce.
nonce = NaCl::Random.random_bytes(cipher.nonce_bytes)

# Encrypt a message with XChaCha20Poly1305
message = "Crystal is amazing" # Message to be encrypted
ad = "" # Additional data sent *in the clear* to be authenticated. This can be `nil`.
ciphertext = cipher.encrypt_string(nonce, message, ad)
# => "..." string of random bytes, 16 bytes longer than the message.
# The extra 16 bytes are the authenticator.

# Decrypt a message, passing in the same additional data we used to encrypt.
decrypted_message = cipher.decrypt_string(nonce, ciphertext, ad)
# => "Crystal is amazing"

# But if the cipher has been tampered with:
cipher.decrypt_string(nonce, corrupted_ciphertext, ad)
# => NaCl::CryptoError

# For encrypting bytes you can use:
ciphertext = cipher.encrypt(nonce, message.bytes, ad)

# And to decrypt back to bytes
decrypted_bytes = cipher.decrypt(nonce, ciphertext, ad)
# => Bytes[...]
```

#### Digital Signatures

##### Signer's Perspective

```crystal
# Generate a new random signing key
signing_key = NaCl::SigningKey.generate

# Message to be signed
message = "Crystal is amazing

# Sign a message with the signing key
signature = signing_key.sign(message)

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Convert the verify key to a string to send it to a third party
verify_key.to_s
```

##### Verifier's Perspective

```crystal
# Create a VerifyKey object from a public key
verify_key = NaCl::VerifyKey.new(verify_key.bytes)

# Check the validity of a message's signature
# Will raise NaCl::BadSignatureError if the signature check fails
verify_key.verify(signature, message)
```

## Supported

- [ ] SimpleBox (simplified cryptography)
- [ ] Secret-key Encryption
  - [ ] [NaCl::SecretBox](#)
  - [x] [NaCl::AEAD::XChaCha20Poly1305](#)
  - [ ] [NaCl::AEAD::ChaCha20Poly1305IETF](#)
  - [ ] [NaCl::AEAD::ChaCha20Poly1305Legacy](#)
- [ ] Public-key Encryption
  -[ ] [NaCl::Box](#)
  -[ ] [NaCl::PrivateKey](#)
  -[ ] [NaCl::PublicKey](#)
- [x] Digital Signatures
  - [x] [NaCl::SigningKey](#)
  - [x] [NaCl::VerifyKey](#)
- [ ] HMAC
  - [ ] [NaCl::HMAC::SHA256](#)
  - [ ] [NaCl::HMAC::SHA512256](#)
- [ ] Hash Functions
  - [ ] [NaCl::Hash](#)
- [ ] Password Hashing
  - [ ] [NaCl::PasswordHash](#)
- [ ] Scalar Manipulation
  - [ ] [NaCl::GroupElement](#)
- [ ] One-time Authentication
- [ ] Random Number Generation
- [x] Utilities
  - [x] Constant-time byte comparison

## Contributing

1. Fork it (<https://github.com/watzon/nacl/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Chris Watson](https://github.com/watzon) - creator and maintainer

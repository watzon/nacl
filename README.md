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

## Supported

- [ ] Secret Key Cryptography
  - [ ] SecretBox
  - [ ] SecretStream
  - [ ] Auth
  - [ ] AEAD
    - [ ] ChaCha20-Poly1305
      - [ ] Original ChaCha20
      - [ ] IETF ChaCha20
      - [x] XChaCha20
    - [ ] AES256-GCM
- [ ] Public Key Cryptography
  - [ ] Box
  - [ ] Sign
  - [ ] SealedBox
- [ ] Hashing
  - [x] GenericHash (Blake2b)
  - [ ] ShortHash
- [ ] Password Hashing
  - [ ] Argon2
- [ ] Key Derivation
- [ ] Key Exchange
- [ ] Others

## Contributing

1. Fork it (<https://github.com/watzon/nacl/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Chris Watson](https://github.com/watzon) - creator and maintainer

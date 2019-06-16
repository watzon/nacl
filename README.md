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
  - [ ] GenericHash
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

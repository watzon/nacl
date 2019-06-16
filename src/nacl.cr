require "./nacl/version"
require "./nacl/sodium"
require "./nacl/key_comparator"
require "./nacl/serializable"
require "./nacl/error"
require "./nacl/util"
require "./nacl/random"
require "./nacl/aead/base"

  # Digital Signatures: Ed25519
require "./nacl/signatures/ed25519"
require "./nacl/signatures/ed25519/verify_key"
require "./nacl/signatures/ed25519/signing_key"

# Hash functions: Blake2b
require "./nacl/hash/blake2b"

# AEAD: ChaCha20-Poly1305
require "./nacl/aead/chacha20poly1305_legacy"
require "./nacl/aead/chacha20poly1305_ietf"
require "./nacl/aead/xchacha20poly1305_ietf"

module NaCl
  alias SigningKey = NaCl::Signatures::Ed25519::SigningKey
  alias VerifyKey = NaCl::Signatures::Ed25519::VerifyKey
end

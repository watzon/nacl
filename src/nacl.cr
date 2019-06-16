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
  SigningKey = NaCl::Signatures::Ed25519::SigningKey
  VerifyKey = NaCl::Signatures::Ed25519::VerifyKey
end

# Generate a new random signing key
signing_key = NaCl::SigningKey.generate

# Message to be signed
message = "Crystal is amazing!"

# Sign a message with the signing key
signature = signing_key.sign(message)

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Convert the verify key to a string to send it to a third party
verify_key.to_s

# Create a VerifyKey object from a public key
verify_key = NaCl::VerifyKey.new(verify_key.bytes)

# Check the validity of a message's signature
# Will raise RbNaCl::BadSignatureError if the signature check fails
puts verify_key.verify(signature, message)

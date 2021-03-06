module NaCl
  module Signatures
    module Ed25519
      # Private key for producing digital signatures using the Ed25519 algorithm.
      # Ed25519 provides a 128-bit security level, that is to say, all known attacks
      # take at least 2^128 operations, providing the same security level as
      # AES-128, NIST P-256, and RSA-3072.
      #
      # Signing keys are produced from a 32-byte (256-bit) random seed value.
      # This value can be passed into the SigningKey constructor as a String
      # whose bytesize is 32.
      #
      # The public VerifyKey can be computed from the private 32-byte seed value
      # as well, eliminating the need to store a "keypair".
      #
      # SigningKey produces 64-byte (512-bit) signatures. The signatures are
      # deterministic: signing the same message will always produce the same
      # signature. This prevents "entropy failure" seen in other signature
      # algorithms like DSA and ECDSA, where poor random number generators can
      # leak enough information to recover the private key.
      class SigningKey
        include KeyComparator
        include Serializable

        @seed : Bytes
        @signing_key : Bytes

        getter verify_key : VerifyKey

        # Generate a random SigningKey
        def self.generate
          SigningKey.new(NaCl::Random.random_bytes(Ed25519::SEEDBYTES))
        end

        # Create a SigningKey from a seed value
        def initialize(seed)
          Util.check_length(seed, Ed25519::SEEDBYTES, "seed")

          pk = Util.zeros(Ed25519::VERIFYKEYBYTES)
          sk = Util.zeros(Ed25519::SIGNINGKEYBYTES)

          LibSodium.crypto_sign_ed25519_seed_keypair(pk, sk, seed) || raise CryptoError.new("Failed to generate a key pair")

          @seed = seed
          @signing_key = sk
          @verify_key = Ed25519::VerifyKey.new(pk)
        end

        # Sign a message using this key
        def sign(message)
          buffer = Util.prepend_zeros(signature_bytes, message)
          buffer_len = Util.zeros(64).map(&.to_u64)

          LibSodium.crypto_sign_ed25519(buffer, buffer_len, message, message.bytesize, @signing_key)

          buffer[0, signature_bytes]
        end

        # Return the raw seed value of this key
        def bytes
          @seed
        end

        # Return the raw 64 byte value of this key
        def keypair_bytes
          @signing_key
        end

        # The size of signatures generated by the SigningKey class
        def self.signature_bytes
          Ed25519::SIGNATUREBYTES
        end

        # The size of signatures generated by the SigningKey instance
        def signature_bytes
          Ed25519::SIGNATUREBYTES
        end
      end
    end
  end
end

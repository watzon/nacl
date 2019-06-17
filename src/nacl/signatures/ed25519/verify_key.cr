module NaCl
  module Signatures
    module Ed25519
      class VerifyKey
        include KeyComparator
        include Serializable

        @key : Bytes

        # Create a new VerifyKey object from a public key.
        def initialize(@key : Bytes)
          Util.check_length(@key, Ed25519::VERIFYKEYBYTES, "key")
        end

        # Verify a signature for a given message
        #
        # Raises if the signature is invalid.
        def verify(signature, message)
          Util.check_length(signature, signature_bytes, "signature")

          sig_and_msg = Util.slice_concat(signature, message.bytes)

          buffer = Util.zeros(sig_and_msg.bytesize)
          buffer_len = Util.zeros(64).map(&.to_u64)

          success = LibSodium.crypto_sign_ed25519_open(buffer, buffer_len, sig_and_msg, sig_and_msg.bytesize, @key)
          raise BadSignatureError.new("signature was forged/corrupt") unless success

          true
        end

        def self.signature_bytes
          Ed25519::SIGNATUREBYTES
        end

        def signature_bytes
          Ed25519::SIGNATUREBYTES
        end

        def bytes
          @key
        end
      end
    end
  end
end

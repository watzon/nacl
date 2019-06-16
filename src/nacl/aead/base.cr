module NaCl
  module AEAD
    abstract class Base
      MESSAGEBYTES_MAX = LibSodium::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
      KEYBYTES         = LibSodium::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES
      NPUBBYTES        = LibSodium::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
      NSECBYTES        = LibSodium::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES
      ABYTES           = LibSodium::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES

      getter key : Indexable(UInt8)

      def initialize(@key : Indexable(UInt8))
      end

      abstract def do_encrypt(ciphertext, ciphertext_len, nonce, message, additional_data)
      abstract def do_decrypt(message, message_len, nonce, ciphertext, additional_data)

      # Encrypts and authenticates a message with additional authenticated data
      def encrypt(nonce, message, additional_data = nil)
        Util.check_length(nonce, nonce_bytes, "Nonce")

        ciphertext_len = Util.zeros(1).map(&.to_u64).to_unsafe
        ciphertext = Util.zeros(data_len(message) + tag_bytes)

        success = do_encrypt(ciphertext, ciphertext_len, nonce, message, additional_data)
        raise NaCl::CryptoError.new("Encryption failed") unless success

        ciphertext
      end

      # Same as `encrypt`, but accepts a `String` message
      def encrypt_string(nonce, message, additional_data = nil)
        message = message.to_slice
        encrypt(nonce, message, additional_data)
      end

      # Decrypts and verifies an encrypted message with additional authenticated data
      def decrypt(nonce, ciphertext, additional_data = nil)
        Util.check_length(nonce, nonce_bytes, "Nonce")

        message_len = Util.zeros(1).map(&.to_u64).to_unsafe
        message = Util.zeros(data_len(ciphertext) - tag_bytes)

        success = do_decrypt(message, message_len, nonce, ciphertext, additional_data)
        raise NaCl::CryptoError.new("Decryption failed. Ciphertext failed verification.") unless success

        message
      end

      # Same as `decrypt`, but returns a `String`
      def decrypt_string(nonce, ciphertext, additional_data = nil, encoding = "utf8")
        message = decrypt(nonce, ciphertext, additional_data)
        String.new(message, encoding)
      end

      # The nonce bytes for the AEAD class
      def self.nonce_bytes
        NPUBBYTES
      end

      # The nonce bytes for the AEAD instance
      def nonce_bytes
        self.class.nonce_bytes
      end

      # The key bytes for the AEAD class
      def self.key_bytes
        KEYBYTES
      end

      # The key bytes for the AEAD instance
      def key_bytes
        self.class.key_bytes
      end

      # The number bytes in the tag or authenticator from this AEAD class
      def self.tag_bytes
        ABYTES
      end

      # The number of bytes in the tag or authenticator for this AEAD instance
      def tag_bytes
        self.class.tag_bytes
      end

      private def data_len(data)
        return 0 if data.nil?
        data.bytesize
      end
    end
  end
end

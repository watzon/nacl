module NaCl
  module AEAD
    # The XChaCha20-Poly1305 construction can safely encrypt a practically unlimited number of
    # messages with the same key, without any practical limit to the size of a
    # message (up to ~ 2^64 bytes).
    #
    # As an alternative to counters, its large nonce size (192-bit) allows random
    # nonces to be safely used.
    #
    # For this reason, and if interoperability with other libraries is not a concern, this is
    # the recommended AEAD construction.
    class XChaCha20Poly1305

      @key : Pointer(UInt8)

      def initialize(key)
        @key = to_u8_pointer(key)
      end

      def encrypt(nonce, data, additional_data = nil)
        abytes = LibSodium.crypto_aead_xchacha20poly1305_ietf_abytes
        ciphertext_len = Pointer(UInt64).malloc(data.size + abytes)
        ciphertext = data.to_unsafe

        nonce = to_u8_pointer(nonce)

        LibSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          ciphertext,
          ciphertext_len,
          data,
          data.size,
          additional_data,
          additional_data.nil? ? 0 : additional_data.size,
          nil,
          nonce,
          @key
        )

        ciphertext.to_slice(ciphertext_len.value)
      end

      def encrypt_string(nonce, string, additional_data = nil)
        self.encrypt(nonce, string.bytes, additional_data)
      end

      def decrypt(nonce, ciphertext, key, additional_data = nil)
        decrypted_len = Pointer(UInt64).malloc(ciphertext.size)
        decrypted = ciphertext.to_unsafe

        nonce = to_u8_pointer(nonce)

        result = LibSodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          decrypted,
          decrypted_len,
          nil,
          ciphertext,
          ciphertext.size,
          additional_data,
          additional_data.nil? ? 0 : additional_data.size,
          nonce,
          @key
        )

        if result < 0
          raise NaCl::CryptoError.new
        else
          decrypted.to_slice(decrypted_len.value)
        end
      end

      def decrypt_string(nonce, ciphertext, additional_data = nil)
        bytes = self.decrypt(nonce, ciphertext, additional_data = nil)
        String.new(bytes.as(Bytes))
      end

      def nonce_bytes
        StaticArray(UInt8, 24).new(0)
      end

      def self.key_bytes
        StaticArray(UInt8, 32).new(0)
      end

      def self.keygen
        buff = XChaCha20Poly1305.key_bytes
        LibSodium.crypto_aead_xchacha20poly1305_ietf_keygen(buff)
        buff
      end

      private def to_u8_pointer(data : Pointer | String | Indexable)
        case data
        when Pointer
          data
        when String
          data.bytes.map(&.to_u8).to_unsafe
        when Indexable
          data.to_a.map(&.to_u8).to_unsafe
        else
          raise ArgumentError.new("Expected one of: Pointer(UInt8), String, Indexible. Got #{typeof(data)}.")
        end
      end
    end
  end
end

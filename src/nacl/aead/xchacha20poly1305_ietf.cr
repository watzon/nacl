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
    #
    # For documentation on all AEAD methods, see `AEAD::Base`.
    class XChaCha20Poly1305 < AEAD::Base
      def do_encrypt(ciphertext, ciphertext_len, nonce, message, additional_data = nil)
        LibSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, ciphertext_len,
          message, data_len(message),
          additional_data, data_len(additional_data),
          nil, nonce, @key)
      end

      def do_decrypt(message, message_len, nonce, ciphertext, additional_data = nil)
        LibSodium.crypto_aead_xchacha20poly1305_ietf_decrypt(message, message_len, nil,
          ciphertext, data_len(ciphertext),
          additional_data, data_len(additional_data),
          nonce, @key)
      end

      def self.keygen
        buff = StaticArray(UInt8, KEYBYTES).new(0)
        LibSodium.crypto_aead_xchacha20poly1305_ietf_keygen(buff)
        buff
      end
    end
  end
end

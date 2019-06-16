module NaCl
  module Crypto
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
      module XChaCha20
        extend self

        NPUBBYTES = LibSodium.crypto_aead_xchacha20poly1305_ietf_npubbytes
        KEYBYTES = LibSodium.crypto_aead_xchacha20poly1305_ietf_keybytes
        ABYTES = LibSodium.crypto_aead_xchacha20poly1305_ietf_abytes

        def keygen(buffer : StaticArray(UInt8, 32)? = nil)
          buff = buffer || StaticArray(UInt8, 32).new(0)
          LibSodium.crypto_aead_xchacha20poly1305_ietf_keygen(buff)
          buff
        end

        def noncegen(buffer : Indexable(UInt8)? = nil)
          buff = buffer || Array(UInt8).new(NPUBBYTES, 0)
          NaCl::RandomBytes.randombytes_buf(buff)
        end

        def encrypt(bytes, nonce, key, additional_data = nil)
          ciphertext_len = Pointer(UInt64).malloc(bytes.size + ABYTES)
          ciphertext = bytes.to_unsafe

          nonce = self.to_u8_pointer(nonce)
          key = self.to_u8_pointer(key)

          LibSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            ciphertext_len,
            bytes,
            bytes.size,
            additional_data,
            additional_data.nil? ? 0 : additional_data.size,
            nil,
            nonce,
            key
          )
          ciphertext.to_slice(ciphertext_len.value)
        end

        def encrypt_string(string, nonce, key, additional_data = nil)
          self.encrypt(string.bytes, nonce, key, additional_data)
        end

        def decrypt(data, nonce, key, additional_data = nil)
          decrypted_len = Pointer(UInt64).malloc(data.size)
          decrypted = data.to_unsafe

          nonce = self.to_u8_pointer(nonce)
          key = self.to_u8_pointer(key)

          result = LibSodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted,
            decrypted_len,
            nil,
            data,
            data.size,
            additional_data,
            additional_data.nil? ? 0 : additional_data.size,
            nonce,
            key
          )

          if result < 0
            false
          else
            decrypted.to_slice(decrypted_len.value)
          end
        end

        def decrypt_string(data, nonce, key, additional_data = nil)
          bytes = self.decrypt(data, nonce, key, additional_data = nil)
          if bytes
            String.new(bytes.as(Bytes))
          else
            false
          end
        end

        private def to_u8_pointer(data)
          case data
          when Pointer
            data
          when String
            self.to_u8_pointer(data.bytes)
          when Indexable
            data.map(&.to_u8).to_unsafe
          end
        end
      end
    end
  end
end

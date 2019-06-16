module NaCl
  module Hash
    class Blake2b

      alias State = LibSodium::CryptoGenerichashState

      BYTES_MAX = LibSodium::CRYPTO_KDF_BLAKE2B_BYTES_MAX
      BYTES_MIN = LibSodium::CRYPTO_KDF_BLAKE2B_BYTES_MIN
      KEYBYTES_MAX = LibSodium::CRYPTO_KDF_BLAKE2B_KEYBYTES_MAX
      KEYBYTES_MIN = LibSodium::CRYPTO_KDF_BLAKE2B_KEYBYTES_MIN
      CONTEXTBYTES = LibSodium::CRYPTO_KDF_BLAKE2B_CONTEXTBYTES
      KEYBYTES = LibSodium::CRYPTO_KDF_BLAKE2B_KEYBYTES
      PERSONALBYTES = LibSodium::CRYPTO_KDF_BLAKE2B_PERSONALBYTES
      SALTBYTES = LibSodium::CRYPTO_KDF_BLAKE2B_SALTBYTES

      EMPTY_PERSONAL = "\0" * PERSONALBYTES
      EMPTY_SALT = "\0" * SALTBYTES

      @key : Pointer(UInt8)?
      @key_size : Int32
      @digest : Pointer(UInt8)
      @digest_size : Int32
      @personal : Pointer(UInt8)?
      @salt : Pointer(UInt8)?
      @incycle : Bool
      @instate : State

      def self.digest(message, key = nil, digest_size = nil, salt = nil, personal = nil)
        if key
          key_size = key.bytesize
          raise NaCl::LengthError.new("key too short") if key_size < KEYBYTES_MIN
          raise NaCl::LengthError.new("key too long") if key_size > KEYBYTES_MAX
        else
          key_size = 0
        end

        digest_size ||= BYTES_MAX
        raise LengthError.new("digest size too short") if digest_size < BYTES_MIN
        raise LengthError.new("digest size too long") if digest_size > BYTES_MAX

        personal ||= EMPTY_PERSONAL
        personal = Util.zero_pad(PERSONALBYTES, personal)

        salt ||= EMPTY_SALT
        salt = Util.zero_pad(SALTBYTES, salt)

        digest = Util.zeros(digest_size)
        LibSodium.crypto_generichash_blake2b_salt_personal(digest, digest_size, message, message.bytesize,
          key, key_size, salt, personal) || raise CryptoError.new("Hashing failed!")

        digest
      end

      def initialize(key = nil, digest_size = nil, personal = nil, salt = nil)
        @key = key
        @key_size = key.nil? ? 0 : key.bytesize
        @digest_size = digest_size || BYTES_MAX
        @digest = Pointer(UInt8).null
        @personal = personal
        @salt = salt

        @incycle = false
        @instate = State.new
      end

      def reset
        # @instate.not_nil!.release if @instate
        @instate = State.new
        LibSodium.crypto_generichash_blake2b_init_salt_personal(pointerof(@instate), @key, @key_size, @digest_size, @salt, @personal) ||
          raise CryptoError.new("Hash init failed!")
        @incycle = true
        @digest = Pointer(UInt8).null
      end

      def update(message)
        reset unless @incycle
        LibSodium.crypto_generichash_blake2b_update(pointerof(@instate), message, message.bytesize) ||
          raise CryptoError.new("Hashing failed!")
      end

      def digest
        raise CryptoError.new("No message to hash yet!") unless @incycle
        return @digest.to_slice(@digest_size) unless @digest.null?
        @digest = Pointer(UInt8).malloc(@digest_size)
        LibSodium.crypto_generichash_blake2b_final(pointerof(@instate), @digest, @digest_size) ||
          raise CryptoError.new("Hash finalization failed!")
        @digest.to_slice(@digest_size)
      end
    end
  end
end

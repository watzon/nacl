module NaCl
  class Error < Exception; end
  class CryptoError < Error; end
  class LengthError < Error; end
  class BadSignatureError < Error; end
end

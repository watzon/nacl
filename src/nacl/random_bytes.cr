module NaCl
  module RandomBytes
    extend self

    def randombytes_buf(buffer : Indexable(UInt8))
      LibSodium.randombytes_buf(buffer, buffer.size)
      buffer
    end
  end
end

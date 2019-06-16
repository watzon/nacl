module NaCl
  module Random
    extend self

    def random_bytes(buffer : Indexable(UInt8))
      LibSodium.randombytes_buf(buffer, buffer.size)
      buffer
    end
  end
end

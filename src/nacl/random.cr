module NaCl
  module Random
    extend self

    def random_bytes(n = 32)
      mutex = Mutex.new
      buf = Util.zeros(n)
      mutex.synchronize { LibSodium.randombytes_buf(buf, n) }
      buf.to_slice
    end
  end
end

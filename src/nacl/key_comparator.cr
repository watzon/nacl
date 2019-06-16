module NaCl
  module KeyComparator
    include Comparable(KeyComparator)

    def <=>(other)
      if other.responds_to?(:bytes)
        other = other.bytes
      else
        other = other.to_s.bytes
      end

      compare32(other)
    end

    def ==(other)
      if other.responds_to?(:bytes)
        other = other.bytes
      else
        other = other.to_s.bytes
      end

      Util.verify32(other)
    end

    def compare32(other)
      if Util.verify32(bytes, other)
        0
      elsif bytes > other
        1
      else
        -1
      end
    end
  end
end

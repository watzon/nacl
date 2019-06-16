module NaCl
  module Serializable
    def to_s
      bytes.hexstring
    end

    def inspect
      cls = self.class.to_s.split("::")[-2, 2].join("::")
      "#<#{cls}:#{bytes.hexstring[0, 8]}>"
    end
  end
end

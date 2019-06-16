module NaCl
  module Util
    extend self

# Returns a string of n zeros
    #
    # Lots of the functions require us to create strings to pass into functions of a specified size.
    #
    # @param [Integer] n the size of the string to make
    #
    # @return [String] A nice collection of zeros
    def zeros(n = 32)
      "\0" * n
    end

    # Prepends a message with zeros
    #
    # Many functions require a string with some zeros prepended.
    #
    # @param [Integer] n The number of zeros to prepend
    # @param [String] message The string to be prepended
    #
    # @return [String] a bunch of zeros
    def prepend_zeros(n, message)
      zeros(n) + message
    end

    # Remove zeros from the start of a message
    #
    # Many functions require a string with some zeros prepended, then need them removing after.
    # Note: this modifies the passed in string
    #
    # @param [Integer] n The number of zeros to remove
    # @param [String] message The string to be slice
    #
    # @return [String] less a bunch of zeros
    def remove_zeros(n, message)
      message[n, message.bytesize - n]
    end

    # Pad a string out to n characters with zeros
    #
    # @param [Integer] n The length of the resulting string
    # @param [String]  message the message to be padded
    #
    # @raise [RbNaCl::LengthError] If the string is too long
    #
    # @return [String] A string, n bytes long
    def zero_pad(n, message)
      len = message.bytesize
      if len == n
        message
      elsif len > n
        raise LengthError.new("String too long for zero-padding to #{n} bytes")
      else
        message + zeros(n - len)
      end
    end
  end
end

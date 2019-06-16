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
      ("\0" * n).to_slice
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
      zeros(n) + message.to_slice
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
        message.to_slice
      elsif len > n
        raise LengthError.new("String too long for zero-padding to #{n} bytes")
      else
        message.to_slice + zeros(n - len)
      end
    end

    # Check the length of the passed in collection
    #
    # In several places through the codebase we have to be VERY strict with
    # what length of string we accept.  This method supports that.
    def check_length(collection, length, description)
      if collection.empty?
        # code below is run only in test cases
        raise LengthError.new("#{description} was empty (Expected size of #{length.to_i})")
      end

      if collection.bytesize != length.to_i
        raise LengthError.new("#{description} was #{collection.bytesize} bytes (Expected #{length.to_i})")
      end

      true
    end
  end
end

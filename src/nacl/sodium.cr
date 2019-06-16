@[Link(ldflags: "-lsodium")]
lib LibSodium
  alias Uint32T = X__Uint32T
  alias X__Uint32T = LibC::UInt
end

require "./sodium/crypto.cr"
require "./sodium/randombytes.cr"
require "./sodium/utils.cr"

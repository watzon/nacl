@[Link(ldflags: "-lsodium")]
lib LibSodium
  alias Uint32T = X__Uint32T
  alias X__Uint32T = LibC::UInt
end

require "./crypto.cr"
require "./randombytes.cr"
require "./utils.cr"

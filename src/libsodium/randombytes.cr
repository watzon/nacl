@[Link(ldflags: "-lsodium")]
lib LibSodium
  $randombytes_salsa20_implementation : RandombytesImplementation
  $randombytes_sysrandom_implementation : RandombytesImplementation
  fun randombytes_buf(buf : Void*, size : LibC::SizeT)
  fun randombytes_buf_deterministic(buf : Void*, size : LibC::SizeT, seed : UInt8[32])
  fun randombytes_close : LibC::Int
  fun randombytes_implementation_name : LibC::Char*
  fun randombytes_random : Uint32T
  fun randombytes_seedbytes : LibC::SizeT
  fun randombytes_set_implementation(impl : RandombytesImplementation*) : LibC::Int
  fun randombytes_stir
  fun randombytes_uniform(upper_bound : Uint32T) : Uint32T

  struct RandombytesImplementation
    implementation_name : (-> LibC::Char*)
    random : (-> Uint32T)
    stir : (-> Void)
    uniform : (Uint32T -> Uint32T)
    buf : (Void*, LibC::SizeT -> Void)
    close : (-> LibC::Int)
  end
end

@[Link(ldflags: "-lsodium")]
lib LibSodium
  SODIUM_BASE64_VARIANT_ORIGINAL            = 1
  SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING = 3
  SODIUM_BASE64_VARIANT_URLSAFE             = 5
  SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING  = 7
  fun sodium_add(a : UInt8*, b : UInt8*, len : LibC::SizeT)
  fun sodium_allocarray(count : LibC::SizeT, size : LibC::SizeT) : Void*
  fun sodium_base642bin(bin : UInt8*, bin_maxlen : LibC::SizeT, b64 : LibC::Char*, b64_len : LibC::SizeT, ignore : LibC::Char*, bin_len : LibC::SizeT*, b64_end : LibC::Char**, variant : LibC::Int) : LibC::Int
  fun sodium_base64_encoded_len(bin_len : LibC::SizeT, variant : LibC::Int) : LibC::SizeT
  fun sodium_bin2base64(b64 : LibC::Char*, b64_maxlen : LibC::SizeT, bin : UInt8*, bin_len : LibC::SizeT, variant : LibC::Int) : LibC::Char*
  fun sodium_bin2hex(hex : LibC::Char*, hex_maxlen : LibC::SizeT, bin : UInt8*, bin_len : LibC::SizeT) : LibC::Char*
  fun sodium_compare(b1_ : UInt8*, b2_ : UInt8*, len : LibC::SizeT) : LibC::Int
  fun sodium_free(ptr : Void*)
  fun sodium_hex2bin(bin : UInt8*, bin_maxlen : LibC::SizeT, hex : LibC::Char*, hex_len : LibC::SizeT, ignore : LibC::Char*, bin_len : LibC::SizeT*, hex_end : LibC::Char**) : LibC::Int
  fun sodium_increment(n : UInt8*, nlen : LibC::SizeT)
  fun sodium_init : LibC::Int
  fun sodium_is_zero(n : UInt8*, nlen : LibC::SizeT) : LibC::Int
  fun sodium_library_minimal : LibC::Int
  fun sodium_library_version_major : LibC::Int
  fun sodium_library_version_minor : LibC::Int
  fun sodium_malloc(size : LibC::SizeT) : Void*
  fun sodium_memcmp(b1_ : Void*, b2_ : Void*, len : LibC::SizeT) : LibC::Int
  fun sodium_memzero(pnt : Void*, len : LibC::SizeT)
  fun sodium_misuse
  fun sodium_mlock(addr : Void*, len : LibC::SizeT) : LibC::Int
  fun sodium_mprotect_noaccess(ptr : Void*) : LibC::Int
  fun sodium_mprotect_readonly(ptr : Void*) : LibC::Int
  fun sodium_mprotect_readwrite(ptr : Void*) : LibC::Int
  fun sodium_munlock(addr : Void*, len : LibC::SizeT) : LibC::Int
  fun sodium_pad(padded_buflen_p : LibC::SizeT*, buf : UInt8*, unpadded_buflen : LibC::SizeT, blocksize : LibC::SizeT, max_buflen : LibC::SizeT) : LibC::Int
  fun sodium_runtime_has_aesni : LibC::Int
  fun sodium_runtime_has_avx : LibC::Int
  fun sodium_runtime_has_avx2 : LibC::Int
  fun sodium_runtime_has_avx512f : LibC::Int
  fun sodium_runtime_has_neon : LibC::Int
  fun sodium_runtime_has_pclmul : LibC::Int
  fun sodium_runtime_has_rdrand : LibC::Int
  fun sodium_runtime_has_sse2 : LibC::Int
  fun sodium_runtime_has_sse3 : LibC::Int
  fun sodium_runtime_has_sse41 : LibC::Int
  fun sodium_runtime_has_ssse3 : LibC::Int
  fun sodium_set_misuse_handler(handler : (-> Void)) : LibC::Int
  fun sodium_stackzero(len : LibC::SizeT)
  fun sodium_sub(a : UInt8*, b : UInt8*, len : LibC::SizeT)
  fun sodium_unpad(unpadded_buflen_p : LibC::SizeT*, buf : UInt8*, padded_buflen : LibC::SizeT, blocksize : LibC::SizeT) : LibC::Int
  fun sodium_version_string : LibC::Char*
end

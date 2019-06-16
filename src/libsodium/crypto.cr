@[Link(ldflags: "-lsodium")]
lib LibSodium
  CRYPTO_CORE_ED25519_BYTES                         = 32
  CRYPTO_CORE_ED25519_NONREDUCEDSCALARBYTES         = 64
  CRYPTO_CORE_ED25519_SCALARBYTES                   = 32
  CRYPTO_CORE_ED25519_UNIFORMBYTES                  = 32
  CRYPTO_KDF_BLAKE2B_BYTES_MAX                      = 64
  CRYPTO_KDF_BLAKE2B_BYTES_MIN                      = 16
  CRYPTO_KDF_BLAKE2B_CONTEXTBYTES                   =  8
  CRYPTO_KDF_BLAKE2B_KEYBYTES                       = 32
  CRYPTO_KX_PUBLICKEYBYTES                          = 32
  CRYPTO_KX_SECRETKEYBYTES                          = 32
  CRYPTO_KX_SEEDBYTES                               = 32
  CRYPTO_KX_SESSIONKEYBYTES                         = 32
  CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13             =  2
  CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13               =  1
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE =  0
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH    =  1
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY   =  2
  alias CryptoAuthHmacsha512256State = CryptoAuthHmacsha512State
  alias CryptoGenerichashState = CryptoGenerichashBlake2bState
  alias CryptoOnetimeauthState = CryptoOnetimeauthPoly1305State
  alias CryptoSignState = CryptoSignEd25519phState
  alias Uint64T = X__Uint64T
  alias Uint8T = X__Uint8T
  alias X__Uint64T = LibC::ULong
  alias X__Uint8T = UInt8
  fun crypto_aead_aes256gcm_abytes : LibC::SizeT
  fun crypto_aead_aes256gcm_beforenm(ctx_ : CryptoAeadAes256gcmState*, k : UInt8*) : LibC::Int
  fun crypto_aead_aes256gcm_decrypt(m : UInt8*, mlen_p : LibC::ULongLong*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_aes256gcm_decrypt_afternm(m : UInt8*, mlen_p : LibC::ULongLong*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, ctx_ : CryptoAeadAes256gcmState*) : LibC::Int
  fun crypto_aead_aes256gcm_decrypt_detached(m : UInt8*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, mac : UInt8*, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_aes256gcm_decrypt_detached_afternm(m : UInt8*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, mac : UInt8*, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, ctx_ : CryptoAeadAes256gcmState*) : LibC::Int
  fun crypto_aead_aes256gcm_encrypt(c : UInt8*, clen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_aes256gcm_encrypt_afternm(c : UInt8*, clen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, ctx_ : CryptoAeadAes256gcmState*) : LibC::Int
  fun crypto_aead_aes256gcm_encrypt_detached(c : UInt8*, mac : UInt8*, maclen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_aes256gcm_encrypt_detached_afternm(c : UInt8*, mac : UInt8*, maclen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, ctx_ : CryptoAeadAes256gcmState*) : LibC::Int
  fun crypto_aead_aes256gcm_is_available : LibC::Int
  fun crypto_aead_aes256gcm_keybytes : LibC::SizeT
  fun crypto_aead_aes256gcm_keygen(k : UInt8[32])
  fun crypto_aead_aes256gcm_messagebytes_max : LibC::SizeT
  fun crypto_aead_aes256gcm_npubbytes : LibC::SizeT
  fun crypto_aead_aes256gcm_nsecbytes : LibC::SizeT
  fun crypto_aead_aes256gcm_statebytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_abytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_decrypt(m : UInt8*, mlen_p : LibC::ULongLong*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_decrypt_detached(m : UInt8*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, mac : UInt8*, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_encrypt(c : UInt8*, clen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_encrypt_detached(c : UInt8*, mac : UInt8*, maclen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_ietf_abytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_ietf_decrypt(m : UInt8*, mlen_p : LibC::ULongLong*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_ietf_decrypt_detached(m : UInt8*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, mac : UInt8*, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_ietf_encrypt(c : UInt8*, clen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_ietf_encrypt_detached(c : UInt8*, mac : UInt8*, maclen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_chacha20poly1305_ietf_keybytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_ietf_keygen(k : UInt8[32])
  fun crypto_aead_chacha20poly1305_ietf_messagebytes_max : LibC::SizeT
  fun crypto_aead_chacha20poly1305_ietf_npubbytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_ietf_nsecbytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_keybytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_keygen(k : UInt8[32])
  fun crypto_aead_chacha20poly1305_messagebytes_max : LibC::SizeT
  fun crypto_aead_chacha20poly1305_npubbytes : LibC::SizeT
  fun crypto_aead_chacha20poly1305_nsecbytes : LibC::SizeT
  fun crypto_aead_xchacha20poly1305_ietf_abytes : LibC::SizeT
  fun crypto_aead_xchacha20poly1305_ietf_decrypt(m : UInt8*, mlen_p : LibC::ULongLong*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m : UInt8*, nsec : UInt8*, c : UInt8*, clen : LibC::ULongLong, mac : UInt8*, ad : UInt8*, adlen : LibC::ULongLong, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_xchacha20poly1305_ietf_encrypt(c : UInt8*, clen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c : UInt8*, mac : UInt8*, maclen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, nsec : UInt8*, npub : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_aead_xchacha20poly1305_ietf_keybytes : LibC::SizeT
  fun crypto_aead_xchacha20poly1305_ietf_keygen(k : UInt8[32])
  fun crypto_aead_xchacha20poly1305_ietf_messagebytes_max : LibC::SizeT
  fun crypto_aead_xchacha20poly1305_ietf_npubbytes : LibC::SizeT
  fun crypto_aead_xchacha20poly1305_ietf_nsecbytes : LibC::SizeT
  fun crypto_auth(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_bytes : LibC::SizeT
  fun crypto_auth_hmacsha256(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha256_bytes : LibC::SizeT
  fun crypto_auth_hmacsha256_final(state : CryptoAuthHmacsha256State*, out : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha256_init(state : CryptoAuthHmacsha256State*, key : UInt8*, keylen : LibC::SizeT) : LibC::Int
  fun crypto_auth_hmacsha256_keybytes : LibC::SizeT
  fun crypto_auth_hmacsha256_keygen(k : UInt8[32])
  fun crypto_auth_hmacsha256_statebytes : LibC::SizeT
  fun crypto_auth_hmacsha256_update(state : CryptoAuthHmacsha256State*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_auth_hmacsha256_verify(h : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha512(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha512256(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha512256_bytes : LibC::SizeT
  fun crypto_auth_hmacsha512256_final(state : CryptoAuthHmacsha512256State*, out : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha512256_init(state : CryptoAuthHmacsha512256State*, key : UInt8*, keylen : LibC::SizeT) : LibC::Int
  fun crypto_auth_hmacsha512256_keybytes : LibC::SizeT
  fun crypto_auth_hmacsha512256_keygen(k : UInt8[32])
  fun crypto_auth_hmacsha512256_statebytes : LibC::SizeT
  fun crypto_auth_hmacsha512256_update(state : CryptoAuthHmacsha512256State*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_auth_hmacsha512256_verify(h : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha512_bytes : LibC::SizeT
  fun crypto_auth_hmacsha512_final(state : CryptoAuthHmacsha512State*, out : UInt8*) : LibC::Int
  fun crypto_auth_hmacsha512_init(state : CryptoAuthHmacsha512State*, key : UInt8*, keylen : LibC::SizeT) : LibC::Int
  fun crypto_auth_hmacsha512_keybytes : LibC::SizeT
  fun crypto_auth_hmacsha512_keygen(k : UInt8[32])
  fun crypto_auth_hmacsha512_statebytes : LibC::SizeT
  fun crypto_auth_hmacsha512_update(state : CryptoAuthHmacsha512State*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_auth_hmacsha512_verify(h : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_auth_keybytes : LibC::SizeT
  fun crypto_auth_keygen(k : UInt8[32])
  fun crypto_auth_primitive : LibC::Char*
  fun crypto_auth_verify(h : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_box(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_afternm(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_beforenm(k : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_beforenmbytes : LibC::SizeT
  fun crypto_box_boxzerobytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_beforenm(k : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_beforenmbytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_detached(c : UInt8*, mac : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_detached_afternm(c : UInt8*, mac : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_easy(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_easy_afternm(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_macbytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_messagebytes_max : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_noncebytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_open_detached(m : UInt8*, c : UInt8*, mac : UInt8*, clen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m : UInt8*, c : UInt8*, mac : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_open_easy(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_publickeybytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_seal(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_seal_open(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_sealbytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_secretkeybytes : LibC::SizeT
  fun crypto_box_curve25519xchacha20poly1305_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
  fun crypto_box_curve25519xchacha20poly1305_seedbytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_afternm(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_beforenm(k : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_beforenmbytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_boxzerobytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_macbytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_messagebytes_max : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_noncebytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_open(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_open_afternm(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_publickeybytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_secretkeybytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
  fun crypto_box_curve25519xsalsa20poly1305_seedbytes : LibC::SizeT
  fun crypto_box_curve25519xsalsa20poly1305_zerobytes : LibC::SizeT
  fun crypto_box_detached(c : UInt8*, mac : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_detached_afternm(c : UInt8*, mac : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_easy(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_easy_afternm(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_macbytes : LibC::SizeT
  fun crypto_box_messagebytes_max : LibC::SizeT
  fun crypto_box_noncebytes : LibC::SizeT
  fun crypto_box_open(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_open_afternm(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_open_detached(m : UInt8*, c : UInt8*, mac : UInt8*, clen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_open_detached_afternm(m : UInt8*, c : UInt8*, mac : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_open_easy(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_open_easy_afternm(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_box_primitive : LibC::Char*
  fun crypto_box_publickeybytes : LibC::SizeT
  fun crypto_box_seal(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
  fun crypto_box_seal_open(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_box_sealbytes : LibC::SizeT
  fun crypto_box_secretkeybytes : LibC::SizeT
  fun crypto_box_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
  fun crypto_box_seedbytes : LibC::SizeT
  fun crypto_box_zerobytes : LibC::SizeT
  fun crypto_core_ed25519_add(r : UInt8*, p : UInt8*, q : UInt8*) : LibC::Int
  fun crypto_core_ed25519_bytes : LibC::SizeT
  fun crypto_core_ed25519_from_uniform(p : UInt8*, r : UInt8*) : LibC::Int
  fun crypto_core_ed25519_is_valid_point(p : UInt8*) : LibC::Int
  fun crypto_core_ed25519_nonreducedscalarbytes : LibC::SizeT
  fun crypto_core_ed25519_scalar_add(z : UInt8*, x : UInt8*, y : UInt8*)
  fun crypto_core_ed25519_scalar_complement(comp : UInt8*, s : UInt8*)
  fun crypto_core_ed25519_scalar_invert(recip : UInt8*, s : UInt8*) : LibC::Int
  fun crypto_core_ed25519_scalar_negate(neg : UInt8*, s : UInt8*)
  fun crypto_core_ed25519_scalar_random(r : UInt8*)
  fun crypto_core_ed25519_scalar_reduce(r : UInt8*, s : UInt8*)
  fun crypto_core_ed25519_scalar_sub(z : UInt8*, x : UInt8*, y : UInt8*)
  fun crypto_core_ed25519_scalarbytes : LibC::SizeT
  fun crypto_core_ed25519_sub(r : UInt8*, p : UInt8*, q : UInt8*) : LibC::Int
  fun crypto_core_ed25519_uniformbytes : LibC::SizeT
  fun crypto_core_hchacha20(out : UInt8*, in : UInt8*, k : UInt8*, c : UInt8*) : LibC::Int
  fun crypto_core_hchacha20_constbytes : LibC::SizeT
  fun crypto_core_hchacha20_inputbytes : LibC::SizeT
  fun crypto_core_hchacha20_keybytes : LibC::SizeT
  fun crypto_core_hchacha20_outputbytes : LibC::SizeT
  fun crypto_core_hsalsa20(out : UInt8*, in : UInt8*, k : UInt8*, c : UInt8*) : LibC::Int
  fun crypto_core_hsalsa20_constbytes : LibC::SizeT
  fun crypto_core_hsalsa20_inputbytes : LibC::SizeT
  fun crypto_core_hsalsa20_keybytes : LibC::SizeT
  fun crypto_core_hsalsa20_outputbytes : LibC::SizeT
  fun crypto_core_salsa20(out : UInt8*, in : UInt8*, k : UInt8*, c : UInt8*) : LibC::Int
  fun crypto_core_salsa2012(out : UInt8*, in : UInt8*, k : UInt8*, c : UInt8*) : LibC::Int
  fun crypto_core_salsa2012_constbytes : LibC::SizeT
  fun crypto_core_salsa2012_inputbytes : LibC::SizeT
  fun crypto_core_salsa2012_keybytes : LibC::SizeT
  fun crypto_core_salsa2012_outputbytes : LibC::SizeT
  fun crypto_core_salsa208(out : UInt8*, in : UInt8*, k : UInt8*, c : UInt8*) : LibC::Int
  fun crypto_core_salsa208_constbytes : LibC::SizeT
  fun crypto_core_salsa208_inputbytes : LibC::SizeT
  fun crypto_core_salsa208_keybytes : LibC::SizeT
  fun crypto_core_salsa208_outputbytes : LibC::SizeT
  fun crypto_core_salsa20_constbytes : LibC::SizeT
  fun crypto_core_salsa20_inputbytes : LibC::SizeT
  fun crypto_core_salsa20_keybytes : LibC::SizeT
  fun crypto_core_salsa20_outputbytes : LibC::SizeT
  fun crypto_generichash(out : UInt8*, outlen : LibC::SizeT, in : UInt8*, inlen : LibC::ULongLong, key : UInt8*, keylen : LibC::SizeT) : LibC::Int
  fun crypto_generichash_blake2b(out : UInt8*, outlen : LibC::SizeT, in : UInt8*, inlen : LibC::ULongLong, key : UInt8*, keylen : LibC::SizeT) : LibC::Int
  fun crypto_generichash_blake2b_bytes : LibC::SizeT
  fun crypto_generichash_blake2b_bytes_max : LibC::SizeT
  fun crypto_generichash_blake2b_bytes_min : LibC::SizeT
  fun crypto_generichash_blake2b_final(state : CryptoGenerichashBlake2bState*, out : UInt8*, outlen : LibC::SizeT) : LibC::Int
  fun crypto_generichash_blake2b_init(state : CryptoGenerichashBlake2bState*, key : UInt8*, keylen : LibC::SizeT, outlen : LibC::SizeT) : LibC::Int
  fun crypto_generichash_blake2b_init_salt_personal(state : CryptoGenerichashBlake2bState*, key : UInt8*, keylen : LibC::SizeT, outlen : LibC::SizeT, salt : UInt8*, personal : UInt8*) : LibC::Int
  fun crypto_generichash_blake2b_keybytes : LibC::SizeT
  fun crypto_generichash_blake2b_keybytes_max : LibC::SizeT
  fun crypto_generichash_blake2b_keybytes_min : LibC::SizeT
  fun crypto_generichash_blake2b_keygen(k : UInt8[32])
  fun crypto_generichash_blake2b_personalbytes : LibC::SizeT
  fun crypto_generichash_blake2b_salt_personal(out : UInt8*, outlen : LibC::SizeT, in : UInt8*, inlen : LibC::ULongLong, key : UInt8*, keylen : LibC::SizeT, salt : UInt8*, personal : UInt8*) : LibC::Int
  fun crypto_generichash_blake2b_saltbytes : LibC::SizeT
  fun crypto_generichash_blake2b_statebytes : LibC::SizeT
  fun crypto_generichash_blake2b_update(state : CryptoGenerichashBlake2bState*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_generichash_bytes : LibC::SizeT
  fun crypto_generichash_bytes_max : LibC::SizeT
  fun crypto_generichash_bytes_min : LibC::SizeT
  fun crypto_generichash_final(state : CryptoGenerichashState*, out : UInt8*, outlen : LibC::SizeT) : LibC::Int
  fun crypto_generichash_init(state : CryptoGenerichashState*, key : UInt8*, keylen : LibC::SizeT, outlen : LibC::SizeT) : LibC::Int
  fun crypto_generichash_keybytes : LibC::SizeT
  fun crypto_generichash_keybytes_max : LibC::SizeT
  fun crypto_generichash_keybytes_min : LibC::SizeT
  fun crypto_generichash_keygen(k : UInt8[32])
  fun crypto_generichash_primitive : LibC::Char*
  fun crypto_generichash_statebytes : LibC::SizeT
  fun crypto_generichash_update(state : CryptoGenerichashState*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_hash(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_hash_bytes : LibC::SizeT
  fun crypto_hash_primitive : LibC::Char*
  fun crypto_hash_sha256(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_hash_sha256_bytes : LibC::SizeT
  fun crypto_hash_sha256_final(state : CryptoHashSha256State*, out : UInt8*) : LibC::Int
  fun crypto_hash_sha256_init(state : CryptoHashSha256State*) : LibC::Int
  fun crypto_hash_sha256_statebytes : LibC::SizeT
  fun crypto_hash_sha256_update(state : CryptoHashSha256State*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_hash_sha512(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_hash_sha512_bytes : LibC::SizeT
  fun crypto_hash_sha512_final(state : CryptoHashSha512State*, out : UInt8*) : LibC::Int
  fun crypto_hash_sha512_init(state : CryptoHashSha512State*) : LibC::Int
  fun crypto_hash_sha512_statebytes : LibC::SizeT
  fun crypto_hash_sha512_update(state : CryptoHashSha512State*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_kdf_blake2b_bytes_max : LibC::SizeT
  fun crypto_kdf_blake2b_bytes_min : LibC::SizeT
  fun crypto_kdf_blake2b_contextbytes : LibC::SizeT
  fun crypto_kdf_blake2b_derive_from_key(subkey : UInt8*, subkey_len : LibC::SizeT, subkey_id : Uint64T, ctx : LibC::Char[8], key : UInt8[32]) : LibC::Int
  fun crypto_kdf_blake2b_keybytes : LibC::SizeT
  fun crypto_kdf_bytes_max : LibC::SizeT
  fun crypto_kdf_bytes_min : LibC::SizeT
  fun crypto_kdf_contextbytes : LibC::SizeT
  fun crypto_kdf_derive_from_key(subkey : UInt8*, subkey_len : LibC::SizeT, subkey_id : Uint64T, ctx : LibC::Char[8], key : UInt8[32]) : LibC::Int
  fun crypto_kdf_keybytes : LibC::SizeT
  fun crypto_kdf_keygen(k : UInt8[32])
  fun crypto_kdf_primitive : LibC::Char*
  fun crypto_kx_client_session_keys(rx : UInt8[32], tx : UInt8[32], client_pk : UInt8[32], client_sk : UInt8[32], server_pk : UInt8[32]) : LibC::Int
  fun crypto_kx_keypair(pk : UInt8[32], sk : UInt8[32]) : LibC::Int
  fun crypto_kx_primitive : LibC::Char*
  fun crypto_kx_publickeybytes : LibC::SizeT
  fun crypto_kx_secretkeybytes : LibC::SizeT
  fun crypto_kx_seed_keypair(pk : UInt8[32], sk : UInt8[32], seed : UInt8[32]) : LibC::Int
  fun crypto_kx_seedbytes : LibC::SizeT
  fun crypto_kx_server_session_keys(rx : UInt8[32], tx : UInt8[32], server_pk : UInt8[32], server_sk : UInt8[32], client_pk : UInt8[32]) : LibC::Int
  fun crypto_kx_sessionkeybytes : LibC::SizeT
  fun crypto_onetimeauth(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_onetimeauth_bytes : LibC::SizeT
  fun crypto_onetimeauth_final(state : CryptoOnetimeauthState*, out : UInt8*) : LibC::Int
  fun crypto_onetimeauth_init(state : CryptoOnetimeauthState*, key : UInt8*) : LibC::Int
  fun crypto_onetimeauth_keybytes : LibC::SizeT
  fun crypto_onetimeauth_keygen(k : UInt8[32])
  fun crypto_onetimeauth_poly1305(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_onetimeauth_poly1305_bytes : LibC::SizeT
  fun crypto_onetimeauth_poly1305_final(state : CryptoOnetimeauthPoly1305State*, out : UInt8*) : LibC::Int
  fun crypto_onetimeauth_poly1305_init(state : CryptoOnetimeauthPoly1305State*, key : UInt8*) : LibC::Int
  fun crypto_onetimeauth_poly1305_keybytes : LibC::SizeT
  fun crypto_onetimeauth_poly1305_keygen(k : UInt8[32])
  fun crypto_onetimeauth_poly1305_statebytes : LibC::SizeT
  fun crypto_onetimeauth_poly1305_update(state : CryptoOnetimeauthPoly1305State*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_onetimeauth_poly1305_verify(h : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_onetimeauth_primitive : LibC::Char*
  fun crypto_onetimeauth_statebytes : LibC::SizeT
  fun crypto_onetimeauth_update(state : CryptoOnetimeauthState*, in : UInt8*, inlen : LibC::ULongLong) : LibC::Int
  fun crypto_onetimeauth_verify(h : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_pwhash(out : UInt8*, outlen : LibC::ULongLong, passwd : LibC::Char*, passwdlen : LibC::ULongLong, salt : UInt8*, opslimit : LibC::ULongLong, memlimit : LibC::SizeT, alg : LibC::Int) : LibC::Int
  fun crypto_pwhash_alg_argon2i13 : LibC::Int
  fun crypto_pwhash_alg_argon2id13 : LibC::Int
  fun crypto_pwhash_alg_default : LibC::Int
  fun crypto_pwhash_argon2i(out : UInt8*, outlen : LibC::ULongLong, passwd : LibC::Char*, passwdlen : LibC::ULongLong, salt : UInt8*, opslimit : LibC::ULongLong, memlimit : LibC::SizeT, alg : LibC::Int) : LibC::Int
  fun crypto_pwhash_argon2i_alg_argon2i13 : LibC::Int
  fun crypto_pwhash_argon2i_bytes_max : LibC::SizeT
  fun crypto_pwhash_argon2i_bytes_min : LibC::SizeT
  fun crypto_pwhash_argon2i_memlimit_interactive : LibC::SizeT
  fun crypto_pwhash_argon2i_memlimit_max : LibC::SizeT
  fun crypto_pwhash_argon2i_memlimit_min : LibC::SizeT
  fun crypto_pwhash_argon2i_memlimit_moderate : LibC::SizeT
  fun crypto_pwhash_argon2i_memlimit_sensitive : LibC::SizeT
  fun crypto_pwhash_argon2i_opslimit_interactive : LibC::SizeT
  fun crypto_pwhash_argon2i_opslimit_max : LibC::SizeT
  fun crypto_pwhash_argon2i_opslimit_min : LibC::SizeT
  fun crypto_pwhash_argon2i_opslimit_moderate : LibC::SizeT
  fun crypto_pwhash_argon2i_opslimit_sensitive : LibC::SizeT
  fun crypto_pwhash_argon2i_passwd_max : LibC::SizeT
  fun crypto_pwhash_argon2i_passwd_min : LibC::SizeT
  fun crypto_pwhash_argon2i_saltbytes : LibC::SizeT
  fun crypto_pwhash_argon2i_str(out : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong, opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_argon2i_str_needs_rehash(str : LibC::Char[128], opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_argon2i_str_verify(str : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong) : LibC::Int
  fun crypto_pwhash_argon2i_strbytes : LibC::SizeT
  fun crypto_pwhash_argon2i_strprefix : LibC::Char*
  fun crypto_pwhash_argon2id(out : UInt8*, outlen : LibC::ULongLong, passwd : LibC::Char*, passwdlen : LibC::ULongLong, salt : UInt8*, opslimit : LibC::ULongLong, memlimit : LibC::SizeT, alg : LibC::Int) : LibC::Int
  fun crypto_pwhash_argon2id_alg_argon2id13 : LibC::Int
  fun crypto_pwhash_argon2id_bytes_max : LibC::SizeT
  fun crypto_pwhash_argon2id_bytes_min : LibC::SizeT
  fun crypto_pwhash_argon2id_memlimit_interactive : LibC::SizeT
  fun crypto_pwhash_argon2id_memlimit_max : LibC::SizeT
  fun crypto_pwhash_argon2id_memlimit_min : LibC::SizeT
  fun crypto_pwhash_argon2id_memlimit_moderate : LibC::SizeT
  fun crypto_pwhash_argon2id_memlimit_sensitive : LibC::SizeT
  fun crypto_pwhash_argon2id_opslimit_interactive : LibC::SizeT
  fun crypto_pwhash_argon2id_opslimit_max : LibC::SizeT
  fun crypto_pwhash_argon2id_opslimit_min : LibC::SizeT
  fun crypto_pwhash_argon2id_opslimit_moderate : LibC::SizeT
  fun crypto_pwhash_argon2id_opslimit_sensitive : LibC::SizeT
  fun crypto_pwhash_argon2id_passwd_max : LibC::SizeT
  fun crypto_pwhash_argon2id_passwd_min : LibC::SizeT
  fun crypto_pwhash_argon2id_saltbytes : LibC::SizeT
  fun crypto_pwhash_argon2id_str(out : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong, opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_argon2id_str_needs_rehash(str : LibC::Char[128], opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_argon2id_str_verify(str : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong) : LibC::Int
  fun crypto_pwhash_argon2id_strbytes : LibC::SizeT
  fun crypto_pwhash_argon2id_strprefix : LibC::Char*
  fun crypto_pwhash_bytes_max : LibC::SizeT
  fun crypto_pwhash_bytes_min : LibC::SizeT
  fun crypto_pwhash_memlimit_interactive : LibC::SizeT
  fun crypto_pwhash_memlimit_max : LibC::SizeT
  fun crypto_pwhash_memlimit_min : LibC::SizeT
  fun crypto_pwhash_memlimit_moderate : LibC::SizeT
  fun crypto_pwhash_memlimit_sensitive : LibC::SizeT
  fun crypto_pwhash_opslimit_interactive : LibC::SizeT
  fun crypto_pwhash_opslimit_max : LibC::SizeT
  fun crypto_pwhash_opslimit_min : LibC::SizeT
  fun crypto_pwhash_opslimit_moderate : LibC::SizeT
  fun crypto_pwhash_opslimit_sensitive : LibC::SizeT
  fun crypto_pwhash_passwd_max : LibC::SizeT
  fun crypto_pwhash_passwd_min : LibC::SizeT
  fun crypto_pwhash_primitive : LibC::Char*
  fun crypto_pwhash_saltbytes : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256(out : UInt8*, outlen : LibC::ULongLong, passwd : LibC::Char*, passwdlen : LibC::ULongLong, salt : UInt8*, opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_scryptsalsa208sha256_bytes_max : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_bytes_min : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_ll(passwd : Uint8T*, passwdlen : LibC::SizeT, salt : Uint8T*, saltlen : LibC::SizeT, n : Uint64T, r : Uint32T, p : Uint32T, buf : Uint8T*, buflen : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_scryptsalsa208sha256_memlimit_interactive : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_memlimit_max : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_memlimit_min : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_opslimit_interactive : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_opslimit_max : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_opslimit_min : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_passwd_max : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_passwd_min : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_saltbytes : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_str(out : LibC::Char[102], passwd : LibC::Char*, passwdlen : LibC::ULongLong, opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(str : LibC::Char[102], opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_scryptsalsa208sha256_str_verify(str : LibC::Char[102], passwd : LibC::Char*, passwdlen : LibC::ULongLong) : LibC::Int
  fun crypto_pwhash_scryptsalsa208sha256_strbytes : LibC::SizeT
  fun crypto_pwhash_scryptsalsa208sha256_strprefix : LibC::Char*
  fun crypto_pwhash_str(out : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong, opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_str_alg(out : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong, opslimit : LibC::ULongLong, memlimit : LibC::SizeT, alg : LibC::Int) : LibC::Int
  fun crypto_pwhash_str_needs_rehash(str : LibC::Char[128], opslimit : LibC::ULongLong, memlimit : LibC::SizeT) : LibC::Int
  fun crypto_pwhash_str_verify(str : LibC::Char[128], passwd : LibC::Char*, passwdlen : LibC::ULongLong) : LibC::Int
  fun crypto_pwhash_strbytes : LibC::SizeT
  fun crypto_pwhash_strprefix : LibC::Char*
  fun crypto_scalarmult(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
  fun crypto_scalarmult_base(q : UInt8*, n : UInt8*) : LibC::Int
  fun crypto_scalarmult_bytes : LibC::SizeT
  fun crypto_scalarmult_curve25519(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
  fun crypto_scalarmult_curve25519_base(q : UInt8*, n : UInt8*) : LibC::Int
  fun crypto_scalarmult_curve25519_bytes : LibC::SizeT
  fun crypto_scalarmult_curve25519_scalarbytes : LibC::SizeT
  fun crypto_scalarmult_ed25519(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
  fun crypto_scalarmult_ed25519_base(q : UInt8*, n : UInt8*) : LibC::Int
  fun crypto_scalarmult_ed25519_base_noclamp(q : UInt8*, n : UInt8*) : LibC::Int
  fun crypto_scalarmult_ed25519_bytes : LibC::SizeT
  fun crypto_scalarmult_ed25519_noclamp(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
  fun crypto_scalarmult_ed25519_scalarbytes : LibC::SizeT
  fun crypto_scalarmult_primitive : LibC::Char*
  fun crypto_scalarmult_scalarbytes : LibC::SizeT
  fun crypto_secretbox(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_boxzerobytes : LibC::SizeT
  fun crypto_secretbox_detached(c : UInt8*, mac : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_easy(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_keybytes : LibC::SizeT
  fun crypto_secretbox_keygen(k : UInt8[32])
  fun crypto_secretbox_macbytes : LibC::SizeT
  fun crypto_secretbox_messagebytes_max : LibC::SizeT
  fun crypto_secretbox_noncebytes : LibC::SizeT
  fun crypto_secretbox_open(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_open_detached(m : UInt8*, c : UInt8*, mac : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_open_easy(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_primitive : LibC::Char*
  fun crypto_secretbox_xchacha20poly1305_detached(c : UInt8*, mac : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_xchacha20poly1305_easy(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_xchacha20poly1305_keybytes : LibC::SizeT
  fun crypto_secretbox_xchacha20poly1305_macbytes : LibC::SizeT
  fun crypto_secretbox_xchacha20poly1305_messagebytes_max : LibC::SizeT
  fun crypto_secretbox_xchacha20poly1305_noncebytes : LibC::SizeT
  fun crypto_secretbox_xchacha20poly1305_open_detached(m : UInt8*, c : UInt8*, mac : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_xchacha20poly1305_open_easy(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_xsalsa20poly1305(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_xsalsa20poly1305_boxzerobytes : LibC::SizeT
  fun crypto_secretbox_xsalsa20poly1305_keybytes : LibC::SizeT
  fun crypto_secretbox_xsalsa20poly1305_keygen(k : UInt8[32])
  fun crypto_secretbox_xsalsa20poly1305_macbytes : LibC::SizeT
  fun crypto_secretbox_xsalsa20poly1305_messagebytes_max : LibC::SizeT
  fun crypto_secretbox_xsalsa20poly1305_noncebytes : LibC::SizeT
  fun crypto_secretbox_xsalsa20poly1305_open(m : UInt8*, c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_secretbox_xsalsa20poly1305_zerobytes : LibC::SizeT
  fun crypto_secretbox_zerobytes : LibC::SizeT
  fun crypto_secretstream_xchacha20poly1305_abytes : LibC::SizeT
  fun crypto_secretstream_xchacha20poly1305_headerbytes : LibC::SizeT
  fun crypto_secretstream_xchacha20poly1305_init_pull(state : CryptoSecretstreamXchacha20poly1305State*, header : UInt8[24], k : UInt8[32]) : LibC::Int
  fun crypto_secretstream_xchacha20poly1305_init_push(state : CryptoSecretstreamXchacha20poly1305State*, header : UInt8[24], k : UInt8[32]) : LibC::Int
  fun crypto_secretstream_xchacha20poly1305_keybytes : LibC::SizeT
  fun crypto_secretstream_xchacha20poly1305_keygen(k : UInt8[32])
  fun crypto_secretstream_xchacha20poly1305_messagebytes_max : LibC::SizeT
  fun crypto_secretstream_xchacha20poly1305_pull(state : CryptoSecretstreamXchacha20poly1305State*, m : UInt8*, mlen_p : LibC::ULongLong*, tag_p : UInt8*, c : UInt8*, clen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong) : LibC::Int
  fun crypto_secretstream_xchacha20poly1305_push(state : CryptoSecretstreamXchacha20poly1305State*, c : UInt8*, clen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, ad : UInt8*, adlen : LibC::ULongLong, tag : UInt8) : LibC::Int
  fun crypto_secretstream_xchacha20poly1305_rekey(state : CryptoSecretstreamXchacha20poly1305State*)
  fun crypto_secretstream_xchacha20poly1305_statebytes : LibC::SizeT
  fun crypto_secretstream_xchacha20poly1305_tag_final : UInt8
  fun crypto_secretstream_xchacha20poly1305_tag_message : UInt8
  fun crypto_secretstream_xchacha20poly1305_tag_push : UInt8
  fun crypto_secretstream_xchacha20poly1305_tag_rekey : UInt8
  fun crypto_shorthash(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_shorthash_bytes : LibC::SizeT
  fun crypto_shorthash_keybytes : LibC::SizeT
  fun crypto_shorthash_keygen(k : UInt8[16])
  fun crypto_shorthash_primitive : LibC::Char*
  fun crypto_shorthash_siphash24(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_shorthash_siphash24_bytes : LibC::SizeT
  fun crypto_shorthash_siphash24_keybytes : LibC::SizeT
  fun crypto_shorthash_siphashx24(out : UInt8*, in : UInt8*, inlen : LibC::ULongLong, k : UInt8*) : LibC::Int
  fun crypto_shorthash_siphashx24_bytes : LibC::SizeT
  fun crypto_shorthash_siphashx24_keybytes : LibC::SizeT
  fun crypto_sign(sm : UInt8*, smlen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, sk : UInt8*) : LibC::Int
  fun crypto_sign_bytes : LibC::SizeT
  fun crypto_sign_detached(sig : UInt8*, siglen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519(sm : UInt8*, smlen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_bytes : LibC::SizeT
  fun crypto_sign_ed25519_detached(sig : UInt8*, siglen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_messagebytes_max : LibC::SizeT
  fun crypto_sign_ed25519_open(m : UInt8*, mlen_p : LibC::ULongLong*, sm : UInt8*, smlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_pk_to_curve25519(curve25519_pk : UInt8*, ed25519_pk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_publickeybytes : LibC::SizeT
  fun crypto_sign_ed25519_secretkeybytes : LibC::SizeT
  fun crypto_sign_ed25519_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_seedbytes : LibC::SizeT
  fun crypto_sign_ed25519_sk_to_curve25519(curve25519_sk : UInt8*, ed25519_sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_sk_to_pk(pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_sk_to_seed(seed : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519_verify_detached(sig : UInt8*, m : UInt8*, mlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519ph_final_create(state : CryptoSignEd25519phState*, sig : UInt8*, siglen_p : LibC::ULongLong*, sk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519ph_final_verify(state : CryptoSignEd25519phState*, sig : UInt8*, pk : UInt8*) : LibC::Int
  fun crypto_sign_ed25519ph_init(state : CryptoSignEd25519phState*) : LibC::Int
  fun crypto_sign_ed25519ph_statebytes : LibC::SizeT
  fun crypto_sign_ed25519ph_update(state : CryptoSignEd25519phState*, m : UInt8*, mlen : LibC::ULongLong) : LibC::Int
  fun crypto_sign_final_create(state : CryptoSignState*, sig : UInt8*, siglen_p : LibC::ULongLong*, sk : UInt8*) : LibC::Int
  fun crypto_sign_final_verify(state : CryptoSignState*, sig : UInt8*, pk : UInt8*) : LibC::Int
  fun crypto_sign_init(state : CryptoSignState*) : LibC::Int
  fun crypto_sign_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
  fun crypto_sign_messagebytes_max : LibC::SizeT
  fun crypto_sign_open(m : UInt8*, mlen_p : LibC::ULongLong*, sm : UInt8*, smlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
  fun crypto_sign_primitive : LibC::Char*
  fun crypto_sign_publickeybytes : LibC::SizeT
  fun crypto_sign_secretkeybytes : LibC::SizeT
  fun crypto_sign_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
  fun crypto_sign_seedbytes : LibC::SizeT
  fun crypto_sign_statebytes : LibC::SizeT
  fun crypto_sign_update(state : CryptoSignState*, m : UInt8*, mlen : LibC::ULongLong) : LibC::Int
  fun crypto_sign_verify_detached(sig : UInt8*, m : UInt8*, mlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
  fun crypto_stream(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_chacha20(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_chacha20_ietf(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_chacha20_ietf_keybytes : LibC::SizeT
  fun crypto_stream_chacha20_ietf_keygen(k : UInt8[32])
  fun crypto_stream_chacha20_ietf_messagebytes_max : LibC::SizeT
  fun crypto_stream_chacha20_ietf_noncebytes : LibC::SizeT
  fun crypto_stream_chacha20_ietf_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_chacha20_ietf_xor_ic(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, ic : Uint32T, k : UInt8*) : LibC::Int
  fun crypto_stream_chacha20_keybytes : LibC::SizeT
  fun crypto_stream_chacha20_keygen(k : UInt8[32])
  fun crypto_stream_chacha20_messagebytes_max : LibC::SizeT
  fun crypto_stream_chacha20_noncebytes : LibC::SizeT
  fun crypto_stream_chacha20_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_chacha20_xor_ic(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, ic : Uint64T, k : UInt8*) : LibC::Int
  fun crypto_stream_keybytes : LibC::SizeT
  fun crypto_stream_keygen(k : UInt8[32])
  fun crypto_stream_messagebytes_max : LibC::SizeT
  fun crypto_stream_noncebytes : LibC::SizeT
  fun crypto_stream_primitive : LibC::Char*
  fun crypto_stream_salsa20(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_salsa2012(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_salsa2012_keybytes : LibC::SizeT
  fun crypto_stream_salsa2012_keygen(k : UInt8[32])
  fun crypto_stream_salsa2012_messagebytes_max : LibC::SizeT
  fun crypto_stream_salsa2012_noncebytes : LibC::SizeT
  fun crypto_stream_salsa2012_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_salsa208(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_salsa208_keybytes : LibC::SizeT
  fun crypto_stream_salsa208_keygen(k : UInt8[32])
  fun crypto_stream_salsa208_messagebytes_max : LibC::SizeT
  fun crypto_stream_salsa208_noncebytes : LibC::SizeT
  fun crypto_stream_salsa208_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_salsa20_keybytes : LibC::SizeT
  fun crypto_stream_salsa20_keygen(k : UInt8[32])
  fun crypto_stream_salsa20_messagebytes_max : LibC::SizeT
  fun crypto_stream_salsa20_noncebytes : LibC::SizeT
  fun crypto_stream_salsa20_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_salsa20_xor_ic(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, ic : Uint64T, k : UInt8*) : LibC::Int
  fun crypto_stream_xchacha20(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_xchacha20_keybytes : LibC::SizeT
  fun crypto_stream_xchacha20_keygen(k : UInt8[32])
  fun crypto_stream_xchacha20_messagebytes_max : LibC::SizeT
  fun crypto_stream_xchacha20_noncebytes : LibC::SizeT
  fun crypto_stream_xchacha20_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_xchacha20_xor_ic(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, ic : Uint64T, k : UInt8*) : LibC::Int
  fun crypto_stream_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_xsalsa20(c : UInt8*, clen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_xsalsa20_keybytes : LibC::SizeT
  fun crypto_stream_xsalsa20_keygen(k : UInt8[32])
  fun crypto_stream_xsalsa20_messagebytes_max : LibC::SizeT
  fun crypto_stream_xsalsa20_noncebytes : LibC::SizeT
  fun crypto_stream_xsalsa20_xor(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, k : UInt8*) : LibC::Int
  fun crypto_stream_xsalsa20_xor_ic(c : UInt8*, m : UInt8*, mlen : LibC::ULongLong, n : UInt8*, ic : Uint64T, k : UInt8*) : LibC::Int
  fun crypto_verify_16(x : UInt8*, y : UInt8*) : LibC::Int
  fun crypto_verify_16_bytes : LibC::SizeT
  fun crypto_verify_32(x : UInt8*, y : UInt8*) : LibC::Int
  fun crypto_verify_32_bytes : LibC::SizeT
  fun crypto_verify_64(x : UInt8*, y : UInt8*) : LibC::Int
  fun crypto_verify_64_bytes : LibC::SizeT

  struct CryptoAeadAes256gcmState
    opaque : UInt8[512]
  end

  struct CryptoAuthHmacsha256State
    ictx : CryptoHashSha256State
    octx : CryptoHashSha256State
  end

  struct CryptoAuthHmacsha512State
    ictx : CryptoHashSha512State
    octx : CryptoHashSha512State
  end

  struct CryptoGenerichashBlake2bState
    opaque : UInt8[384]
  end

  struct CryptoHashSha256State
    state : Uint32T[8]
    count : Uint64T
    buf : Uint8T[64]
  end

  struct CryptoHashSha512State
    state : Uint64T[8]
    count : Uint64T[2]
    buf : Uint8T[128]
  end

  struct CryptoOnetimeauthPoly1305State
    opaque : UInt8[256]
  end

  struct CryptoSecretstreamXchacha20poly1305State
    k : UInt8[32]
    nonce : UInt8[12]
    _pad : UInt8[8]
  end

  struct CryptoSignEd25519phState
    hs : CryptoHashSha512State
  end

end

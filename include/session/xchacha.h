#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "export.h"

/// API: crypto/session_xchacha_decrypt
///
/// Wrapper around the crypto_aead_xchacha20poly1305_ietf_decrypt function.
///
/// Inputs:
/// - `ciphertext` -- [in] the data to be decrypted.
/// - `ciphertext_len` -- [in] length of the `ciphertext` data.
/// - `seckey` -- [in] the secret key used to encrypt the data.
/// - `seckey_len` -- [in] length of the `seckey`.
/// - `nonce` -- [in] the nonce used to encrypt the data.
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   encrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption failed.  If
///   (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool session_xchacha_decrypt(
        const unsigned char* ciphertext,
        size_t ciphertext_len,
        const unsigned char* seckey,
        size_t seckey_len,
        const unsigned char* nonce,
        unsigned char** plaintext_out,
        size_t* plaintext_out_len);

#ifdef __cplusplus
}
#endif

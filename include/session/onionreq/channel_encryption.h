#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "../export.h"

typedef enum ENCRYPT_TYPE {
    ENCRYPT_TYPE_AES_GCM = 0,
    ENCRYPT_TYPE_X_CHA_CHA_20 = 1,
} ENCRYPT_TYPE;

/// API: channel_encryption/onion_request_encrypt
///
/// Wrapper around session::onionreq::channel_encryption::encrypt.  message is binary: message
/// has the length provided, pubkey must be exactly 32 bytes. Returns a newly
/// allocated buffer containing the encrypted data, and sets the data's length into
/// `ciphertext_size`.  It is the caller's responsibility to `free()` the returned buffer!
///
/// Declaration:
/// ```cpp
/// UNSIGNED CHAR* onion_request_encrypt(
///     [in]    ENCRYPT_TYPE            type,
///     [in]    const unsigned char*    message,
///     [in]    size_t                  mlen,
///     [in]    const unsigned char*    pubkey,
///     [out]   size_t*                 ciphertext_size
/// );
/// ```
///
/// Inputs:
/// - `type` -- [in] The type of encryption to use
/// - `message` -- [in] The message to encrypted in binary
/// - `mlen` -- [in] Length of the message provided
/// - `pubkey` -- [in] Key, must be binary
/// - `ciphertext_size` -- [out] will contain the size of the returned ciphertext
///
/// Outputs:
/// - `unsigned char*` -- ciphertext, will be nullptr on error
LIBSESSION_EXPORT unsigned char* onion_request_encrypt(
        ENCRYPT_TYPE type,
        const unsigned char* message,
        size_t mlen,
        const unsigned char* pubkey,
        size_t* ciphertext_size);
        
#ifdef __cplusplus
}
#endif
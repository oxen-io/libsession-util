#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32) || defined(WIN32)
#define LIBSESSION_EXPORT __declspec(dllexport)
#else
#define LIBSESSION_EXPORT __attribute__((visibility("default")))
#endif
#define LIBSESSION_C_API extern "C" LIBSESSION_EXPORT

typedef int64_t seqno_t;

/// Wrapper around session::config::encrypt.  message and key_base are binary: message has the
/// length provided, key_base must be exactly 32 bytes.  domain is a c string.  Returns a newly
/// allocated buffer containing the encrypted data, and sets the data's length into
/// `ciphertext_size`.  It is the caller's responsibility to `free()` the returned buffer!
///
/// Returns nullptr on error.
char* config_encrypt(const char* message, size_t mlen,
        const char* key_base,
        const char* domain,
        size_t* ciphertext_size);

/// Works just like config_encrypt, but in reverse.
char* config_decrypt(const char* ciphertext, size_t clen,
        const char* key_base,
        const char* domain,
        size_t* plaintext_size);

#ifdef __cplusplus
}
#endif

#include "session/xchacha.hpp"

#include <sodium/crypto_aead_xchacha20poly1305.h>

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "session/export.h"
#include "session/util.hpp"

namespace session::xchacha {

ustring decrypt(
    ustring_view ciphertext,
    ustring_view seckey,
    ustring_view nonce
) {
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{"Invalid ciphertext: expected to be greater than 16 bytes"};

    ustring buf;
    unsigned long long buf_len = 0;
    buf.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(), &buf_len, nullptr, ciphertext.data(), ciphertext.size(),
                     nullptr, 0, nonce.data(), seckey.data()))
        throw std::runtime_error{"Failed to decrypt; perhaps the secret key is invalid?"};

    return {buf.data(), buf_len};
}

}  // namespace session::xchacha

// using session::xchacha::ustring_view;

extern "C" {

LIBSESSION_C_API bool session_xchacha_decrypt(
        const unsigned char* ciphertext,
        size_t ciphertext_len,
        const unsigned char* seckey,
        size_t seckey_len,
        const unsigned char* nonce,
        unsigned char** plaintext_out,
        size_t* plaintext_out_len) {
    try {
        auto plaintext = session::xchacha::decrypt(
            {ciphertext, ciphertext_len},
            {seckey, seckey_len},
            {nonce, 24}
        );
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_out_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"

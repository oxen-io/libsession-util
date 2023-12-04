#pragma once

#include "types.hpp"

namespace session::xchacha {

/// API: xchacha/decrypt
///
/// Wrapper around the crypto_aead_xchacha20poly1305_ietf_decrypt function.
///
/// Inputs:
/// - `ciphertext` -- the data to be decrypted.
/// - `seckey` -- the secret key used to encrypt the data.
/// - `nonce` -- the nonce used to encrypt the data.
///
/// Outputs:
/// - the plaintext binary data that was encrypted, *if* the message decrypted and validated successfully.  Throws on error.
ustring decrypt(
    ustring_view ciphertext,
    ustring_view seckey,
    ustring_view nonce);

}  // namespace session::xchacha

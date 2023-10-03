#pragma once

#include "types.hpp"

// Helper functions for the "Session Protocol" encryption mechanism.  This is the encryption used
// for DMs sent from one Session user to another.
//
// Suppose Alice with Ed25519 keys `a`/`A` and derived x25519 keys `x`/`X`, wants to send a mesage
// `M` to Brandy with Ed25519 keys `b`/`B` and derived x25519 keys `y`/`Y` (note that the x25519
// pubkeys in hex form are session ids, but without the `05` prefix).
//
// First she signs the message, her own *Ed25519* (not X) pubkey, and the recipients pubkey (X, not
// Ed):
//
//     SIG = Ed25519-sign(M || A || Y)
//
// Next a data message is composed of `M || A || SIG`, then encrypted for Brandy using:
//
//     CIPHERTEXT = crypto_box_seal(M || A || SIG)
//
// (see libsodium for details, but is effectively generating an ephemeral X25519 keypair, making a
// shared secret of that and the recipient key, then encrypting using XSalsa20-Poly1305 from the
// shared secret).
//
// On the decryption side, we do this in reverse and verify via the signature both the sender and
// intended (inner) recipient.  First, Brandy opens the ciphertext and extract the message, sender
// Ed pubkey, and signature:
//
//     M || A || SIG = crypto_box_seal_open(CIPHERTEXT)
//
// then constructs and verifies the expected signature DATA (recall Y = Brandy's X25519 pubkey):
//
//     Ed25519-verify(M || A || Y)
//
// Assuming this passes, we now know that `A` sent the message, and can convert this to a X25519
// pubkey to work out the Session ID:
//
//     X = Ed25519-pubkey-to-curve25519(A)
//
//     SENDER = '05' + hex(X)
//
// and thus Brandy now has decrypted, verified data sent by Alice.

namespace session {

/// API: crypto/encrypt_for_recipient
///
/// Performs session protocol encryption, typically for a DM sent between Session users.
///
/// Inputs:
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes.  Can also be
///   passed as a 32-byte seed, but the 64-byte value is preferrable (to avoid needing to
///   recompute the public key from the seed).
/// - `recipient_pubkey` -- the recipient X25519 pubkey, either as a 0x05-prefixed session ID
///   (33 bytes) or an unprefixed pubkey (32 bytes).
/// - `message` -- the message to encrypt for the recipient.
///
/// Outputs:
/// - The encrypted ciphertext to send.
/// - Throw if encryption fails or (which typically means invalid keys provided)
ustring encrypt_for_recipient(
        ustring_view ed25519_privkey, ustring_view recipient_pubkey, ustring_view message);

/// API: crypto/decrypt_incoming
///
/// Inverse of `encrypt_for_recipient`: this decrypts the message, extracts the sender Ed25519
/// pubkey, and verifies that the sender Ed25519 signature on the message.
///
/// Inputs:
/// - `ed25519_privkey` -- the private key of the recipient.  Can be a 32-byte seed, or a 64-byte
///   libsodium secret key.  The latter is a bit faster as it doesn't have to re-compute the pubkey
///   from the seed.
/// - `ciphertext` -- the encrypted data
///
/// Outputs:
/// - pair consisting of the decrypted message content, and the sender Ed25519 pubkey, *if* the
///   message decrypted and validated successfully.  Throws on error.
///
///   To get the sender's session ID, pass the returned pubkey through
///   crypto_sign_ed25519_pk_to_curve25519.
std::pair<ustring, ustring> decrypt_incoming(ustring_view ed25519_privkey, ustring_view ciphertext);

}  // namespace session

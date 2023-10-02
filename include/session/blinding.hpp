#pragma once

#include <string>
#include <string_view>

#include "util.hpp"

namespace session {

/// Helper functions for community 25xxx blinded ID from a Session pubkey and the server pubkey.
/// This is a verifiable Ed25519 pubkey (prefixed with 25) and is fully deterministic.
///
/// Details: we first compute a blinding factor:
///
///     k = H(SESSION_ID || SERVER_PK) mod L,  where H = 64-byte BLAKE2b
///
/// Next we convert the Session ID (an X25519 pubkey) to Ed25519, and also clear the sign bit
/// (i.e. take the positive).  Thus we give up one bit of the pubkey (because the initial X25519
/// -> Ed25519 conversion lost it).
///
///     X = session id x25519 pubkey
///     A = |Ed(X)| -- i.e. + of the two possible Ed25519 pubkey alternatives for X
///
/// then the blinded pubkey is prefix "25" followed by `kA`.
///
/// To create such a signature, starting from the underlying Ed25519 keypair from seed `s`, with
/// private scalar `z` (NOT the seed) and public key point `S`, we use the same blinding factor
/// to compute private scalar `a` associated with `A`:
///
///     a = z if S is positive (i.e. sign bit is 0)
///     a = -z if S is negative (sign bit is 1)
///
/// which yields our blinded private scalar `ka`.
///
/// From here we generate a signature very similarly to EdDSA, but adapted to this different
/// private signing mechanism.  For a message `M`:
///
///     r = H64(H32(seed, key="SessCommBlind25_seed") || kA || M, key="SessCommBlind25_sig") mod L
///
/// analagously to Ed25519's
///
///     r = SHA512(SHA512(seed)[32:64] || M) mod L
///
/// but using BLAKE2b 64-byte and 32-byte keyed hashes instead of SHA512.  (We also include the
/// `A` in the hash so that the same message with different server_pks will result in different
/// `r` values).
///
/// From there we follow the standard EdDSA construction:
///
///     R = rG
///     S = r + H(R || kA || M) ka   (mod L)
///
/// (using the standard Ed25519 SHA-512 here for H, so that this is verifiable as a standard
/// Ed25519 signature).
///
/// This (R, S) signature is then Ed25519-verifiable using pubkey kA.

/// Returns the blinding factor for 25 blinding.  Typically this isn't used directly, but is
/// exposed for debugging/testing.  Takes session id and pk in bytes, not hex.  session id can
/// be 05-prefixed (33 bytes) or unprefixed (32 bytes).
std::array<unsigned char, 32> blind25_factor(ustring_view session_id, ustring_view server_pk);

/// Computes the 25-blinded id from a session id and server pubkey.  Values accepted and
/// returned are hex-encoded.
std::string blind25_id(std::string_view session_id, std::string_view server_pk);

/// Same as above, but takes the session id and pubkey as byte values instead of hex, and returns a
/// 33-byte value (instead of a 66-digit hex value).  Unlike the string version, session_id here may
/// be passed unprefixed (i.e. 32 bytes instead of 33 with the 05 prefix).
ustring blind25_id(ustring_view session_id, ustring_view server_pk);

/// Computes a verifiable 25-blinded signature that validates with the blinded pubkey that would
/// be returned from blind25_id().
///
/// Takes the Ed25519 secret key (64 bytes, or 32-byte seed) and the server pubkey (in hex (64
/// digits) or bytes (32 bytes)).  Returns the 64-byte signature.
///
/// It is recommended to pass the full 64-byte libsodium-style secret key for `ed25519_sk` (i.e.
/// seed + appended pubkey) as with just the 32-byte seed the public key has to be recomputed.
ustring blind25_sign(ustring_view ed25519_sk, std::string_view server_pk, ustring_view message);

}  // namespace session

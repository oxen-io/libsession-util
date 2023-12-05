#include "session/session_encrypt.hpp"

#include <oxenc/hex.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <session/session_encrypt.h>
#include <sodium/randombytes.h>

#include <array>
#include <cassert>
#include <cstring>
#include <stdexcept>

#include "session/util.hpp"
#include "session/blinding.hpp"

using namespace std::literals;

namespace session {

template <size_t N>
using cleared_array = sodium_cleared<std::array<unsigned char, N>>;

using uc32 = std::array<unsigned char, 32>;
using uc33 = std::array<unsigned char, 33>;
using uc64 = std::array<unsigned char, 64>;
using cleared_uc32 = cleared_array<32>;
using cleared_uc64 = cleared_array<64>;

ustring sign_for_recipient(
        ustring_view ed25519_privkey, ustring_view recipient_pubkey, ustring_view message) {
    cleared_uc64 ed_sk_from_seed;
    if (ed25519_privkey.size() == 32) {
        uc32 ignore_pk;
        crypto_sign_ed25519_seed_keypair(
                ignore_pk.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};
    } else if (ed25519_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    }
    // If prefixed, drop it (and do this for the caller, too) so that everything after this
    // doesn't need to worry about whether it is prefixed or not.
    if (recipient_pubkey.size() == 33 && recipient_pubkey.front() == 0x05)
        recipient_pubkey.remove_prefix(1);
    else if (recipient_pubkey.size() != 32)
        throw std::invalid_argument{
                "Invalid recipient_pubkey: expected 32 bytes (33 with 05 prefix)"};

    ustring buf;
    buf.reserve(message.size() + 96);  // 32+32 now, but 32+64 when we reuse it for the sealed box
    buf += message;
    buf += ed25519_privkey.substr(32);
    buf += recipient_pubkey;

    uc64 sig;
    if (0 != crypto_sign_ed25519_detached(
                     sig.data(), nullptr, buf.data(), buf.size(), ed25519_privkey.data()))
        throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};

    // We have M||A||Y for the sig, but now we want M||A||SIG so drop Y then append SIG:
    buf.resize(buf.size() - 32);
    buf += ustring_view{sig.data(), sig.size()};

    return buf;
}

static const ustring_view BOX_HASHKEY = to_unsigned_sv("SessionBoxEphemeralHashKey"sv);

ustring encrypt_for_recipient(
        ustring_view ed25519_privkey, ustring_view recipient_pubkey, ustring_view message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey.remove_prefix(1);  // sign_for_recipient already checked that this is the
                                            // proper 0x05 prefix when present.

    ustring result;
    result.resize(signed_msg.size() + crypto_box_SEALBYTES);
    if (0 != crypto_box_seal(
                     result.data(), signed_msg.data(), signed_msg.size(), recipient_pubkey.data()))
        throw std::runtime_error{"Sealed box encryption failed"};

    return result;
}

ustring encrypt_for_recipient_deterministic(
        ustring_view ed25519_privkey, ustring_view recipient_pubkey, ustring_view message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey.remove_prefix(1);  // sign_for_recipient already checked that this is the
                                            // proper 0x05 when present.

    // To make our ephemeral seed we're going to hash: SENDER_SEED || RECIPIENT_PK || MESSAGE with a
    // keyed blake2b hash.
    cleared_array<crypto_box_SEEDBYTES> seed;
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, BOX_HASHKEY.data(), BOX_HASHKEY.size(), seed.size());
    crypto_generichash_blake2b_update(&st, ed25519_privkey.data(), 32);
    crypto_generichash_blake2b_update(&st, recipient_pubkey.data(), 32);
    crypto_generichash_blake2b_update(&st, message.data(), message.size());
    crypto_generichash_blake2b_final(&st, seed.data(), seed.size());

    cleared_array<crypto_box_SECRETKEYBYTES> eph_sk;
    cleared_array<crypto_box_PUBLICKEYBYTES> eph_pk;

    crypto_box_seed_keypair(eph_pk.data(), eph_sk.data(), seed.data());

    // The nonce for a sealed box is not passed but is implicitly defined as the (unkeyed) blake2b
    // hash of:
    //     EPH_PUBKEY || RECIPIENT_PUBKEY
    cleared_array<crypto_box_NONCEBYTES> nonce;
    crypto_generichash_blake2b_init(&st, nullptr, 0, nonce.size());
    crypto_generichash_blake2b_update(&st, eph_pk.data(), eph_pk.size());
    crypto_generichash_blake2b_update(&st, recipient_pubkey.data(), recipient_pubkey.size());
    crypto_generichash_blake2b_final(&st, nonce.data(), nonce.size());

    // A sealed box is a regular box (using the ephermal keys and nonce), but with the ephemeral
    // pubkey prepended:
    static_assert(crypto_box_SEALBYTES == crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);

    ustring result;
    result.resize(crypto_box_SEALBYTES + signed_msg.size());
    std::memcpy(result.data(), eph_pk.data(), crypto_box_PUBLICKEYBYTES);
    if (0 != crypto_box_easy(
                     result.data() + crypto_box_PUBLICKEYBYTES,
                     signed_msg.data(),
                     signed_msg.size(),
                     nonce.data(),
                     recipient_pubkey.data(),
                     eph_sk.data()))
        throw std::runtime_error{"Crypto box encryption failed"};

    return result;
}

ustring encrypt_for_blinded_recipient(
    ustring_view ed25519_privkey,
    ustring_view server_pk,
    ustring_view recipient_blinded_id,
    ustring_view message
) {
    if (ed25519_privkey.size() == 64)
        ed25519_privkey.remove_suffix(32);
    else if (ed25519_privkey.size() != 32)
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    if (server_pk.size() != 32)
        throw std::invalid_argument{"Invalid server_pk: expected 32 bytes"};
    if (recipient_blinded_id.size() != 33)
        throw std::invalid_argument{"Invalid recipient_blinded_id: expected 33 bytes"};

    uc32 ed_pk;
    cleared_uc64 ed_sk_from_seed;
    crypto_sign_ed25519_seed_keypair(ed_pk.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
    ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};

    // Generate the blinded key pair & shared encryption key
    std::pair<ustring, ustring> blinded_key_pair;

    switch (recipient_blinded_id[0]) {
        case 0x15:
            blinded_key_pair = blind15_key_pair(ed25519_privkey, server_pk);
            break;

        case 0x25:
            blinded_key_pair = blind25_key_pair(ed25519_privkey, server_pk);
            break;

        default: throw std::invalid_argument{"Invalid recipient_blinded_id: must start with 0x15 or 0x25"};
    }

    // Remove the blinding prefix
    ustring kB = {recipient_blinded_id.data() + 1, 32};
    ustring kA = blinded_key_pair.first;

    // Calculate the shared encryption key, sending from A to B:
    //
    // BLAKE2b(a kB || kA || kB)
    //
    // The receiver can calulate the same value via:
    //
    // BLAKE2b(b kA || kA || kB)
    //
    // Calculate k*a.  To get 'a' (the Ed25519 private key scalar) we call the sodium function to
    // convert to an *x* secret key, which seems wrong--but isn't because converted keys use the
    // same secret scalar secret (and so this is just the most convenient way to get 'a' out of
    // a sodium Ed25519 secret key)
    cleared_uc32 a, sharedSecret;
    uc32 enc_key;
    crypto_generichash_blake2b_state st;
    crypto_sign_ed25519_sk_to_curve25519(a.data(), ed25519_privkey.data());
    if (0 != crypto_scalarmult_ed25519_noclamp(sharedSecret.data(), a.data(), kB.data()))
        throw std::runtime_error{"Shared secret generation failed"};

    crypto_generichash_blake2b_init(&st, nullptr, 0, 32);
    crypto_generichash_blake2b_update(&st, sharedSecret.data(), sharedSecret.size());
    crypto_generichash_blake2b_update(&st, kA.data(), kA.size());
    crypto_generichash_blake2b_update(&st, kB.data(), kB.size());
    crypto_generichash_blake2b_final(&st, enc_key.data(), enc_key.size());

    // Inner data: msg || A (i.e. the sender's ed25519 master pubkey, *not* kA blinded pubkey)
    ustring buf;
    buf.reserve(message.size() + 32);
    buf += message;
    buf += ustring_view{ed_pk.data(), 32};
    
    // Encrypt using xchacha20-poly1305
    cleared_array<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
    randombytes_buf(nonce.data(), nonce.size());

    ustring ciphertext;
    unsigned long long outlen = 0;
    ciphertext.resize(
            buf.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES +
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &outlen, buf.data(), buf.size(), nullptr, 0, nullptr,
        nonce.data(), enc_key.data()))
        throw std::runtime_error{"Crypto aead encryption failed"};

    // data = b'\x00' + ciphertext + nonce
    ciphertext.insert(ciphertext.begin(), 0);
    assert(outlen == ciphertext.size() - 1 - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::memcpy(ciphertext.data() + (1 + outlen), nonce.data(), nonce.size());

    return ciphertext;
}

std::pair<std::string, ustring> decrypt_incoming(
        ustring_view ed25519_privkey, ustring_view ciphertext) {

    cleared_uc64 ed_sk_from_seed;
    if (ed25519_privkey.size() == 32) {
        uc32 ignore_pk;
        crypto_sign_ed25519_seed_keypair(
                ignore_pk.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};
    } else if (ed25519_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    }

    cleared_uc32 x_sec;
    uc32 x_pub;
    crypto_sign_ed25519_sk_to_curve25519(x_sec.data(), ed25519_privkey.data());
    crypto_scalarmult_base(x_pub.data(), x_sec.data());

    return decrypt_incoming({x_pub.data(), 32}, {x_sec.data(), 32}, ciphertext);
}

std::pair<std::string, ustring> decrypt_incoming(
        ustring_view x25519_pubkey, ustring_view x25519_seckey, ustring_view ciphertext) {

    if (ciphertext.size() < crypto_box_SEALBYTES + 32 + 64)
        throw std::runtime_error{"Invalid incoming message: ciphertext is too small"};
    const size_t outer_size = ciphertext.size() - crypto_box_SEALBYTES;
    const size_t msg_size = outer_size - 32 - 64;

    std::pair<std::string, ustring> result;
    auto& [sender_session_id, buf] = result;

    buf.resize(outer_size);
    if (0 != crypto_box_seal_open(
                     buf.data(), ciphertext.data(), ciphertext.size(), x25519_pubkey.data(), x25519_seckey.data()))
        throw std::runtime_error{"Decryption failed"};

    uc64 sig;
    auto sender_ed_pk = buf.substr(msg_size, 32);
    std::memcpy(sig.data(), buf.data() + msg_size + 32, 64);
    buf.resize(buf.size() - 64);  // Remove SIG, then append Y so that we get M||A||Y to verify
    buf += ustring_view{x25519_pubkey.data(), 32};

    if (0 != crypto_sign_ed25519_verify_detached(
                     sig.data(), buf.data(), buf.size(), sender_ed_pk.data()))
        throw std::runtime_error{"Signature verification failed"};

    // Convert the sender_ed_pk to the sender's session ID
    std::array<unsigned char, 32> sender_x_pk;

    if (0 != crypto_sign_ed25519_pk_to_curve25519(
        sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    buf.resize(buf.size() - 32 - 32);
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return result;
}

std::pair<std::string, ustring> decrypt_from_blinded_recipient(
    ustring_view ed25519_privkey,
    ustring_view server_pk,
    ustring_view sender_id,
    ustring_view recipient_id,
    ustring_view ciphertext
) {
    if (ed25519_privkey.size() == 32) {
        uc32 ignore_pk;
        cleared_uc64 ed_sk_from_seed;
        crypto_sign_ed25519_seed_keypair(
                ignore_pk.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};
    } else if (ed25519_privkey.size() != 64)
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    if (server_pk.size() != 32)
        throw std::invalid_argument{"Invalid server_pk: expected 32 bytes"};
    if (sender_id.size() != 33)
        throw std::invalid_argument{"Invalid sender_id: expected 33 bytes"};
    if (recipient_id.size() != 33)
        throw std::invalid_argument{"Invalid recipient_id: expected 33 bytes"};
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 1 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{"Invalid ciphertext: too short to contain valid encrypted data"};

    std::pair<std::string, ustring> result;
    auto& [sender_session_id, buf] = result;

    // Determine whether it's an incoming or outgoing message
    ustring_view kA = {sender_id.data() + 1, 32};
    ustring_view kB = {recipient_id.data() + 1, 32};
    std::pair<ustring, ustring> blinded_key_pair;

    if (recipient_id[0] == 0x15 && sender_id[0] == 0x15) {
        blinded_key_pair = blind15_key_pair(ed25519_privkey, server_pk);
    } else if (recipient_id[0] == 0x25 && sender_id[0] == 0x25) {
        blinded_key_pair = blind25_key_pair(ed25519_privkey, server_pk);
    } else
        throw std::invalid_argument{"Both sender_id and recipient_id must start with the same 0x15 or 0x25 prefix"};

    // Calculate the shared encryption key, sending from A to B:
    //
    // BLAKE2b(a kB || kA || kB)
    //
    // The receiver can calulate the same value via:
    //
    // BLAKE2b(b kA || kA || kB)
    //
    // Calculate k*a.  To get 'a' (the Ed25519 private key scalar) we call the sodium function to
    // convert to an *x* secret key, which seems wrong--but isn't because converted keys use the
    // same secret scalar secret (and so this is just the most convenient way to get 'a' out of
    // a sodium Ed25519 secret key)
    cleared_uc32 a, sharedSecret;
    uc32 dec_key;
    crypto_generichash_blake2b_state st;
    ustring_view dst = (ustring{sender_id.data() + 1, 32} == blinded_key_pair.first ? kB : kA);
    crypto_sign_ed25519_sk_to_curve25519(a.data(), ed25519_privkey.data());
    if (0 != crypto_scalarmult_ed25519_noclamp(sharedSecret.data(), a.data(), dst.data()))
        throw std::runtime_error{"Shared secret generation failed"};

    crypto_generichash_blake2b_init(&st, nullptr, 0, 32);
    crypto_generichash_blake2b_update(&st, sharedSecret.data(), sharedSecret.size());
    crypto_generichash_blake2b_update(&st, kA.data(), kA.size());
    crypto_generichash_blake2b_update(&st, kB.data(), kB.size());
    crypto_generichash_blake2b_final(&st, dec_key.data(), dec_key.size());

    // v, ct, nc = data[0], data[1:-24], data[-24:]
    if (ciphertext[0] != 0)
        throw std::invalid_argument{"Invalid ciphertext: version is not 0"};

    ustring nonce;
    const size_t msg_size = (ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES - 1
        - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned long long buf_len = 0;
    buf.resize(msg_size);
    nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::memcpy(nonce.data(), ciphertext.data() + msg_size + 1 + crypto_aead_xchacha20poly1305_ietf_ABYTES,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
            buf.data(), &buf_len, nullptr, ciphertext.data() + 1,
            ciphertext.size() - 1 - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            nullptr, 0, nonce.data(), dec_key.data()))

    // Ensure the length is correct
    if (buf.size() <= 32)
        throw std::invalid_argument{"Invalid ciphertext: innerBytes too short"};

    // Split up: the last 32 bytes are the sender's *unblinded* ed25519 key
    uc32 sender_ed_pk;
    std::memcpy(sender_ed_pk.data(), buf.data() + (buf.size() - 32), 32);

    // Verify that the inner sender_ed_pk (A) yields the same outer kA we got with the message
    uc32 blindingFactor;
    cleared_uc32 extracted_kA;

    if (sender_id[0] == 0x15)
        blindingFactor = blind15_factor(server_pk);
    else
        blindingFactor = blind25_factor({sender_x_pk.data(), 32}, server_pk);    // TODO: Need to confirm this...

    if (0 != crypto_scalarmult_ed25519_noclamp(extracted_kA.data(), blindingFactor.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Shared secret generation for verification failed"};
    if (kA != ustring_view{extracted_kA.data(), 32})
        throw std::runtime_error{"Shared secret does not match encoded public key"};
        };

    // Everything is good, so just drop the sender_ed_pk off the message and prepend the '05' prefix to
    // the sender session ID
    buf.resize(buf.size() - 32);
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return result;
}

}  // namespace session

using namespace session;

LIBSESSION_C_API bool session_encrypt_for_recipient_deterministic(
    const unsigned char* plaintext_in,
    size_t plaintext_len,
    const unsigned char* ed25519_privkey,
    const unsigned char* recipient_pubkey,
    unsigned char** ciphertext_out,
    size_t* ciphertext_len
) {
    try {
        auto ciphertext = session::encrypt_for_recipient_deterministic(
            ustring_view{ed25519_privkey, 64},
            ustring_view{recipient_pubkey, 32},
            ustring_view{plaintext_in, plaintext_len}
        );

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_encrypt_for_blinded_recipient(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* open_group_pubkey,
        const unsigned char* recipient_blinded_id,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len
) {
    try {
        auto ciphertext = session::encrypt_for_blinded_recipient(
            ustring_view{ed25519_privkey, 64},
            ustring_view{open_group_pubkey, 32},
            ustring_view{recipient_blinded_id, 33},
            ustring_view{plaintext_in, plaintext_len}
        );

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_incoming(
    const unsigned char* ciphertext_in,
    size_t ciphertext_len,
    const unsigned char* ed25519_privkey,
    char* session_id_out,
    unsigned char** plaintext_out,
    size_t* plaintext_len
) {
    try {
        auto result = session::decrypt_incoming(
            ustring_view{ed25519_privkey, 64},
            ustring_view{ciphertext_in, ciphertext_len}
        );
        auto [session_id, plaintext] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_incoming_legacy_group(
    const unsigned char* ciphertext_in,
    size_t ciphertext_len,
    const unsigned char* x25519_pubkey,
    const unsigned char* x25519_seckey,
    char* session_id_out,
    unsigned char** plaintext_out,
    size_t* plaintext_len
) {
    try {
        auto result = session::decrypt_incoming(
            ustring_view{x25519_pubkey, 32},
            ustring_view{x25519_seckey, 32},
            ustring_view{ciphertext_in, ciphertext_len}
        );
        auto [session_id, plaintext] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_for_blinded_recipient(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* open_group_pubkey,
        const unsigned char* sender_id,
        const unsigned char* recipient_id,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len
) {
    try {
        auto result = session::decrypt_from_blinded_recipient(
            ustring_view{ed25519_privkey, 64},
            ustring_view{open_group_pubkey, 32},
            ustring_view{sender_id, 33},
            ustring_view{recipient_id, 33},
            ustring_view{ciphertext_in, ciphertext_len}
        );
        auto [session_id, plaintext] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}
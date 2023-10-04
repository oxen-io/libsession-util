#include "session/session_encrypt.hpp"

#include <sodium/crypto_box.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_sign_ed25519.h>

#include <array>
#include <cassert>
#include <cstring>
#include <stdexcept>

#include "session/util.hpp"

using namespace std::literals;

namespace session {

template <size_t N>
using cleared_array = sodium_cleared<std::array<unsigned char, N>>;

using uc32 = std::array<unsigned char, 32>;
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

std::pair<ustring, ustring> decrypt_incoming(
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

    if (ciphertext.size() < crypto_box_SEALBYTES + 32 + 64)
        throw std::runtime_error{"Invalid incoming message: ciphertext is too small"};
    const size_t outer_size = ciphertext.size() - crypto_box_SEALBYTES;
    const size_t msg_size = outer_size - 32 - 64;

    cleared_uc32 x_sec;
    uc32 x_pub;
    crypto_sign_ed25519_sk_to_curve25519(x_sec.data(), ed25519_privkey.data());
    crypto_scalarmult_base(x_pub.data(), x_sec.data());

    std::pair<ustring, ustring> result;
    auto& [buf, sender_ed_pk] = result;

    buf.resize(outer_size);
    if (0 != crypto_box_seal_open(
                     buf.data(), ciphertext.data(), ciphertext.size(), x_pub.data(), x_sec.data()))
        throw std::runtime_error{"Decryption failed"};

    uc64 sig;
    sender_ed_pk = buf.substr(msg_size, 32);
    std::memcpy(sig.data(), buf.data() + msg_size + 32, 64);
    buf.resize(buf.size() - 64);  // Remove SIG, then append Y so that we get M||A||Y to verify
    buf += ustring_view{x_pub.data(), 32};

    if (0 != crypto_sign_ed25519_verify_detached(
                     sig.data(), buf.data(), buf.size(), sender_ed_pk.data()))
        throw std::runtime_error{"Signature verification failed"};

    // Everything is good, so just drop A and Y off the message
    buf.resize(buf.size() - 32 - 32);

    return result;
}

}  // namespace session

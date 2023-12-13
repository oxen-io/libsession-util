#include "session/blinding.hpp"

#include <oxenc/hex.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>

#include <cassert>
#include <stdexcept>

#include "session/export.h"
#include "session/xed25519.hpp"

namespace session {

using namespace std::literals;

using uc32 = std::array<unsigned char, 32>;
using uc33 = std::array<unsigned char, 33>;
using uc64 = std::array<unsigned char, 64>;

std::array<unsigned char, 32> blind15_factor(ustring_view server_pk) {
    assert(server_pk.size() == 32);

    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, nullptr, 0, 64);
    crypto_generichash_blake2b_update(&st, server_pk.data(), server_pk.size());
    uc64 blind_hash;
    crypto_generichash_blake2b_final(&st, blind_hash.data(), blind_hash.size());

    uc32 k;
    crypto_core_ed25519_scalar_reduce(k.data(), blind_hash.data());
    return k;
}

std::array<unsigned char, 32> blind25_factor(ustring_view session_id, ustring_view server_pk) {
    assert(session_id.size() == 32 || session_id.size() == 33);
    assert(server_pk.size() == 32);

    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, nullptr, 0, 64);
    if (session_id.size() == 32) {
        constexpr unsigned char prefix = 0x05;
        crypto_generichash_blake2b_update(&st, &prefix, 1);
    }
    crypto_generichash_blake2b_update(&st, session_id.data(), session_id.size());
    crypto_generichash_blake2b_update(&st, server_pk.data(), server_pk.size());
    uc64 blind_hash;
    crypto_generichash_blake2b_final(&st, blind_hash.data(), blind_hash.size());

    uc32 k;
    crypto_core_ed25519_scalar_reduce(k.data(), blind_hash.data());
    return k;
}

namespace {

    void blind15_id_impl(ustring_view session_id, ustring_view server_pk, unsigned char* out) {
        auto k = blind15_factor(server_pk);
        if (session_id.size() == 33)
            session_id.remove_prefix(1);
        auto ed_pk = xed25519::pubkey(session_id);
        if (0 != crypto_scalarmult_ed25519_noclamp(out + 1, k.data(), ed_pk.data()))
            throw std::runtime_error{"Cannot blind: invalid session_id (not on main subgroup)"};
        out[0] = 0x15;
    }

    void blind25_id_impl(ustring_view session_id, ustring_view server_pk, unsigned char* out) {
        auto k = blind25_factor(session_id, server_pk);
        if (session_id.size() == 33)
            session_id.remove_prefix(1);
        auto ed_pk = xed25519::pubkey(session_id);
        if (0 != crypto_scalarmult_ed25519_noclamp(out + 1, k.data(), ed_pk.data()))
            throw std::runtime_error{"Cannot blind: invalid session_id (not on main subgroup)"};
        out[0] = 0x25;
    }

}  // namespace

ustring blind15_id(ustring_view session_id, ustring_view server_pk) {
    if (session_id.size() == 33) {
        if (session_id[0] != 0x05)
            throw std::invalid_argument{"blind15_id: session_id must start with 0x05"};
        session_id.remove_prefix(1);
    } else if (session_id.size() != 32) {
        throw std::invalid_argument{"blind15_id: session_id must be 32 or 33 bytes"};
    }
    if (server_pk.size() != 32)
        throw std::invalid_argument{"blind15_id: server_pk must be 32 bytes"};

    ustring result;
    result.resize(33);
    blind15_id_impl(session_id, server_pk, result.data());
    return result;
}

std::string blind15_id(std::string_view session_id, std::string_view server_pk) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{"blind15_id: session_id must be hex (66 digits)"};
    if (session_id[0] != '0' || session_id[1] != '5')
        throw std::invalid_argument{"blind15_id: session_id must start with 05"};
    if (server_pk.size() != 64 || !oxenc::is_hex(server_pk))
        throw std::invalid_argument{"blind15_id: server_pk must be hex (64 digits)"};

    uc33 raw_sid;
    oxenc::from_hex(session_id.begin(), session_id.end(), raw_sid.begin());
    uc32 raw_server_pk;
    oxenc::from_hex(server_pk.begin(), server_pk.end(), raw_server_pk.begin());

    uc33 blinded;
    blind15_id_impl(to_sv(raw_sid), to_sv(raw_server_pk), blinded.data());
    return oxenc::to_hex(blinded.begin(), blinded.end());
}

ustring blind25_id(ustring_view session_id, ustring_view server_pk) {
    if (session_id.size() == 33) {
        if (session_id[0] != 0x05)
            throw std::invalid_argument{"blind25_id: session_id must start with 0x05"};
    } else if (session_id.size() != 32) {
        throw std::invalid_argument{"blind25_id: session_id must be 32 or 33 bytes"};
    }
    if (server_pk.size() != 32)
        throw std::invalid_argument{"blind25_id: server_pk must be 32 bytes"};

    ustring result;
    result.resize(33);
    blind25_id_impl(session_id, server_pk, result.data());
    return result;
}

std::string blind25_id(std::string_view session_id, std::string_view server_pk) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{"blind25_id: session_id must be hex (66 digits)"};
    if (session_id[0] != '0' || session_id[1] != '5')
        throw std::invalid_argument{"blind25_id: session_id must start with 05"};
    if (server_pk.size() != 64 || !oxenc::is_hex(server_pk))
        throw std::invalid_argument{"blind25_id: server_pk must be hex (64 digits)"};

    uc33 raw_sid;
    oxenc::from_hex(session_id.begin(), session_id.end(), raw_sid.begin());
    uc32 raw_server_pk;
    oxenc::from_hex(server_pk.begin(), server_pk.end(), raw_server_pk.begin());

    uc33 blinded;
    blind25_id_impl(to_sv(raw_sid), to_sv(raw_server_pk), blinded.data());
    return oxenc::to_hex(blinded.begin(), blinded.end());
}

std::pair<ustring, ustring> blind15_key_pair(ustring_view ed25519_sk, ustring_view server_pk) {
    std::array<unsigned char, 64> ed_sk_tmp;
    if (ed25519_sk.size() == 32) {
        std::array<unsigned char, 32> pk_ignore;
        crypto_sign_ed25519_seed_keypair(pk_ignore.data(), ed_sk_tmp.data(), ed25519_sk.data());
        ed25519_sk = {ed_sk_tmp.data(), 64};
    }
    if (ed25519_sk.size() != 64)
        throw std::invalid_argument{
                "blind15_key_pair: Invalid ed25519_sk is not the expected 32- or 64-byte value"};

    if (server_pk.size() != 32)
        throw std::invalid_argument{"blind15_key_pair: server_pk must be 32 bytes"};

    /// Generate the blinding factor
    uc32 k = blind15_factor(server_pk);

    /// Generate a scalar for the private key
    uc32 x_sk;
    if (0 != crypto_sign_ed25519_sk_to_curve25519(x_sk.data(), ed25519_sk.data()))
        throw std::runtime_error{
                "blind15_key_pair: Invalid ed25519_sk; conversion to curve25519 seckey failed"};

    // Turn a, A into their blinded versions
    uc32 a;
    uc32 A;
    crypto_core_ed25519_scalar_mul(a.data(), k.data(), x_sk.data());
    crypto_scalarmult_ed25519_base_noclamp(A.data(), a.data());

    return {{A.data(), 32}, {a.data(), 32}};
}

std::pair<ustring, ustring> blind25_key_pair(ustring_view ed25519_sk, ustring_view server_pk) {
    std::array<unsigned char, 64> ed_sk_tmp;
    if (ed25519_sk.size() == 32) {
        std::array<unsigned char, 32> pk_ignore;
        crypto_sign_ed25519_seed_keypair(pk_ignore.data(), ed_sk_tmp.data(), ed25519_sk.data());
        ed25519_sk = {ed_sk_tmp.data(), 64};
    }
    if (ed25519_sk.size() != 64)
        throw std::invalid_argument{
                "blind15_key_pair: Invalid ed25519_sk is not the expected 32- or 64-byte value"};

    if (server_pk.size() != 32)
        throw std::invalid_argument{"blind15_key_pair: server_pk must be 32 bytes"};

    ustring_view S{ed25519_sk.data() + 32, 32};

    uc33 session_id;
    session_id[0] = 0x05;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(session_id.data() + 1, ed25519_sk.data() + 32))
        throw std::runtime_error{
                "blind25_sign: Invalid ed25519_sk; conversion to curve25519 pubkey failed"};

    ustring_view X{session_id.data() + 1, 32};

    /// Generate the blinding factor
    auto k = blind25_factor(X, {server_pk.data(), server_pk.size()});

    /// Generate a scalar for the private key
    uc32 x_sk;
    if (0 != crypto_sign_ed25519_sk_to_curve25519(x_sk.data(), ed25519_sk.data()))
        throw std::runtime_error{
                "blind25_key_pair: Invalid ed25519_sk; conversion to curve25519 seckey failed"};

    // Turn a, A into their blinded versions
    uc32 a;
    uc32 A;
    std::memcpy(A.data(), S.data(), 32);
    if (S[31] & 0x80) {
        // Ed25519 pubkey is negative, so we need to negate `z` to make things come out right
        crypto_core_ed25519_scalar_negate(a.data(), x_sk.data());
        A[31] &= 0x7f;
    } else
        std::memcpy(a.data(), x_sk.data(), 32);

    // Turn a, A into their blinded versions
    crypto_core_ed25519_scalar_mul(a.data(), k.data(), a.data());
    crypto_scalarmult_ed25519_base_noclamp(A.data(), a.data());

    return {{A.data(), 32}, {a.data(), 32}};
}

static const auto hash_key_seed = to_unsigned_sv("SessCommBlind25_seed"sv);
static const auto hash_key_sig = to_unsigned_sv("SessCommBlind25_sig"sv);

ustring blind25_sign(ustring_view ed25519_sk, std::string_view server_pk_in, ustring_view message) {
    std::array<unsigned char, 64> ed_sk_tmp;
    if (ed25519_sk.size() == 32) {
        std::array<unsigned char, 32> pk_ignore;
        crypto_sign_ed25519_seed_keypair(pk_ignore.data(), ed_sk_tmp.data(), ed25519_sk.data());
        ed25519_sk = {ed_sk_tmp.data(), 64};
    }
    if (ed25519_sk.size() != 64)
        throw std::invalid_argument{
                "blind25_sign: Invalid ed25519_sk is not the expected 32- or 64-byte value"};
    uc32 server_pk;
    if (server_pk_in.size() == 32)
        std::memcpy(server_pk.data(), server_pk_in.data(), 32);
    else if (server_pk_in.size() == 64 && oxenc::is_hex(server_pk_in))
        oxenc::from_hex(server_pk_in.begin(), server_pk_in.end(), server_pk.begin());
    else
        throw std::invalid_argument{"blind25_sign: Invalid server_pk: expected 32 bytes or 64 hex"};

    ustring_view S{ed25519_sk.data() + 32, 32};

    uc32 z;
    crypto_sign_ed25519_sk_to_curve25519(z.data(), ed25519_sk.data());

    uc33 session_id;
    session_id[0] = 0x05;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(session_id.data() + 1, ed25519_sk.data() + 32))
        throw std::runtime_error{
                "blind25_sign: Invalid ed25519_sk; conversion to curve25519 pubkey failed"};

    ustring_view X{session_id.data() + 1, 32};

    auto k = blind25_factor(X, {server_pk.data(), server_pk.size()});

    uc32 a;
    uc32 A;
    std::memcpy(A.data(), S.data(), 32);
    if (S[31] & 0x80) {
        // Ed25519 pubkey is negative, so we need to negate `z` to make things come out right
        crypto_core_ed25519_scalar_negate(a.data(), z.data());
        A[31] &= 0x7f;
    } else
        std::memcpy(a.data(), z.data(), 32);

    // Turn a, A into their blinded versions
    crypto_core_ed25519_scalar_mul(a.data(), k.data(), a.data());
    crypto_scalarmult_ed25519_base_noclamp(A.data(), a.data());

    uc32 seedhash;
    crypto_generichash_blake2b(
            seedhash.data(),
            seedhash.size(),
            ed25519_sk.data(),
            32,
            hash_key_seed.data(),
            hash_key_seed.size());

    uc64 r_hash;
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, hash_key_sig.data(), hash_key_sig.size(), r_hash.size());
    crypto_generichash_blake2b_update(&st, seedhash.data(), seedhash.size());
    crypto_generichash_blake2b_update(&st, A.data(), A.size());
    crypto_generichash_blake2b_update(&st, message.data(), message.size());
    crypto_generichash_blake2b_final(&st, r_hash.data(), r_hash.size());

    uc32 r;
    crypto_core_ed25519_scalar_reduce(r.data(), r_hash.data());

    ustring result;
    result.resize(64);
    auto* sig_R = result.data();
    auto* sig_S = result.data() + 32;
    crypto_scalarmult_ed25519_base_noclamp(sig_R, r.data());

    crypto_hash_sha512_state st2;
    crypto_hash_sha512_init(&st2);
    crypto_hash_sha512_update(&st2, sig_R, 32);
    crypto_hash_sha512_update(&st2, A.data(), A.size());
    crypto_hash_sha512_update(&st2, message.data(), message.size());
    uc64 hram;
    crypto_hash_sha512_final(&st2, hram.data());

    crypto_core_ed25519_scalar_reduce(sig_S, hram.data());  // S = H(R||A||M)

    crypto_core_ed25519_scalar_mul(sig_S, sig_S, a.data());  // S = H(R||A||M) a
    crypto_core_ed25519_scalar_add(sig_S, sig_S, r.data());  // S = r + H(R||A||M) a

    return result;
}

ustring blind15_sign(ustring_view ed25519_sk, std::string_view server_pk_in, ustring_view message) {
    std::array<unsigned char, 64> ed_sk_tmp;
    if (ed25519_sk.size() == 32) {
        std::array<unsigned char, 32> pk_ignore;
        crypto_sign_ed25519_seed_keypair(pk_ignore.data(), ed_sk_tmp.data(), ed25519_sk.data());
        ed25519_sk = {ed_sk_tmp.data(), 64};
    }
    if (ed25519_sk.size() != 64)
        throw std::invalid_argument{
                "blind15_sign: Invalid ed25519_sk is not the expected 32- or 64-byte value"};

    uc32 server_pk;
    if (server_pk_in.size() == 32)
        std::memcpy(server_pk.data(), server_pk_in.data(), 32);
    else if (server_pk_in.size() == 64 && oxenc::is_hex(server_pk_in))
        oxenc::from_hex(server_pk_in.begin(), server_pk_in.end(), server_pk.begin());
    else
        throw std::invalid_argument{"blind15_sign: Invalid server_pk: expected 32 bytes or 64 hex"};

    auto [blind_15_pk, blind_15_sk] = blind15_key_pair(ed25519_sk, {server_pk.data(), 32});

    // H_rh = sha512(s.encode()).digest()[32:]
    uc64 hrh;
    crypto_hash_sha512_state st1;
    crypto_hash_sha512_init(&st1);
    crypto_hash_sha512_update(&st1, ed25519_sk.data(), 64);
    crypto_hash_sha512_final(&st1, hrh.data());

    // r = salt.crypto_core_ed25519_scalar_reduce(sha512_multipart(H_rh, kA, message_parts))
    auto hrh_suffix = hrh.data() + 32;
    uc32 r;
    uc64 r_hash;
    crypto_hash_sha512_state st2;
    crypto_hash_sha512_init(&st2);
    crypto_hash_sha512_update(&st2, hrh_suffix, 32);
    crypto_hash_sha512_update(&st2, blind_15_pk.data(), blind_15_pk.size());
    crypto_hash_sha512_update(&st2, message.data(), message.size());
    crypto_hash_sha512_final(&st2, r_hash.data());
    crypto_core_ed25519_scalar_reduce(r.data(), r_hash.data());

    // sig_R = salt.crypto_scalarmult_ed25519_base_noclamp(r)
    ustring result;
    result.resize(64);
    auto* sig_R = result.data();
    auto* sig_S = result.data() + 32;
    crypto_scalarmult_ed25519_base_noclamp(sig_R, r.data());

    // HRAM = salt.crypto_core_ed25519_scalar_reduce(sha512_multipart(sig_R, kA, message_parts))
    uc64 hram;
    crypto_hash_sha512_state st3;
    crypto_hash_sha512_init(&st3);
    crypto_hash_sha512_update(&st3, sig_R, 32);
    crypto_hash_sha512_update(&st3, blind_15_pk.data(), blind_15_pk.size());
    crypto_hash_sha512_update(&st3, message.data(), message.size());
    crypto_hash_sha512_final(&st3, hram.data());

    // sig_s = salt.crypto_core_ed25519_scalar_add(r, salt.crypto_core_ed25519_scalar_mul(HRAM, ka))
    crypto_core_ed25519_scalar_reduce(sig_S, hram.data());             // S = H(R||A||M)
    crypto_core_ed25519_scalar_mul(sig_S, sig_S, blind_15_sk.data());  // S = H(R||A||M) a
    crypto_core_ed25519_scalar_add(sig_S, sig_S, r.data());            // S = r + H(R||A||M) a

    return result;
}

bool session_id_matches_blinded_id(
        std::string_view session_id, std::string_view blinded_id, std::string_view server_pk) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{
                "session_id_matches_blinded_id: session_id must be hex (66 digits)"};
    if (session_id[0] != '0' || session_id[1] != '5')
        throw std::invalid_argument{"session_id_matches_blinded_id: session_id must start with 05"};
    if (blinded_id[1] != '5' && (blinded_id[0] != '1' || blinded_id[0] != '2'))
        throw std::invalid_argument{
                "session_id_matches_blinded_id: blinded_id must start with 15 or 25"};
    if (server_pk.size() != 64 || !oxenc::is_hex(server_pk))
        throw std::invalid_argument{
                "session_id_matches_blinded_id: server_pk must be hex (64 digits)"};

    std::string converted_blind_id1, converted_blind_id2;
    ustring converted_blind_id1_raw;

    switch (blinded_id[0]) {
        case '1':
            converted_blind_id1 = blind15_id(session_id, server_pk);

            // For the negative, what we're going to get out of the above is simply the negative of
            // converted_blind_id1, so flip the sign bit to get converted_blind_id2
            oxenc::from_hex(
                    converted_blind_id1.begin(),
                    converted_blind_id1.end(),
                    std::back_inserter(converted_blind_id1_raw));
            converted_blind_id1_raw[32] ^= 0x80;
            converted_blind_id2 = oxenc::to_hex(converted_blind_id1_raw);

            return (blinded_id == converted_blind_id1 || blinded_id == converted_blind_id2);

        // blind25 doesn't run into the negative issue that blind15 did
        case '2': return blinded_id == blind25_id(session_id, server_pk);
        default: throw std::invalid_argument{"Invalid blinded_id: must start with 15 or 25"};
    }
}

}  // namespace session

using namespace session;

LIBSESSION_C_API bool session_blind15_key_pair(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        unsigned char* blinded_pk_out,
        unsigned char* blinded_sk_out) {
    try {
        auto result = session::blind15_key_pair({ed25519_seckey, 64}, {server_pk, 32});
        auto [b_pk, b_sk] = result;
        std::memcpy(blinded_pk_out, b_pk.data(), b_pk.size());
        std::memcpy(blinded_sk_out, b_sk.data(), b_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind25_key_pair(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        unsigned char* blinded_pk_out,
        unsigned char* blinded_sk_out) {
    try {
        auto result = session::blind25_key_pair({ed25519_seckey, 64}, {server_pk, 32});
        auto [b_pk, b_sk] = result;
        std::memcpy(blinded_pk_out, b_pk.data(), b_pk.size());
        std::memcpy(blinded_sk_out, b_sk.data(), b_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind15_sign(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        const unsigned char* msg,
        size_t msg_len,
        unsigned char* blinded_sig_out) {
    try {
        auto result = session::blind15_sign(
                {ed25519_seckey, 64}, {from_unsigned(server_pk), 32}, {msg, msg_len});
        auto sig = result;
        std::memcpy(blinded_sig_out, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind25_sign(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        const unsigned char* msg,
        size_t msg_len,
        unsigned char* blinded_sig_out) {
    try {
        auto result = session::blind25_sign(
                {ed25519_seckey, 64}, {from_unsigned(server_pk), 32}, {msg, msg_len});
        auto sig = result;
        std::memcpy(blinded_sig_out, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_id_matches_blinded_id(
        const char* session_id, const char* blinded_id, const char* server_pk) {
    try {
        return session::session_id_matches_blinded_id(
                {session_id, 66}, {blinded_id, 66}, {server_pk, 64});
    } catch (...) {
        return false;
    }
}
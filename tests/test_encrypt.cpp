#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <iterator>
#include <random>
#include <session/config.hpp>
#include <session/config/encrypt.hpp>
#include <session/types.hpp>

#include "utils.hpp"

using namespace session;
using namespace std::literals;
using namespace oxenc::literals;

TEST_CASE("config message encryption", "[config][encrypt]") {
    auto message1 = "some message 1"_bytes;
    auto key1 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_hexbytes;
    auto key2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;
    auto enc1 = config::encrypt(message1, key1, "test-suite1");
    CHECK(oxenc::to_hex(enc1.begin(), enc1.end()) ==
          "f14f242a26638f3305707d1035e734577f943cd7d28af58e32637e"
          "0966dcaf2f4860cb4d0f8ba7e09d29e31f5e4a18f65847287a54a0");
    auto enc2 = config::encrypt(message1, key1, "test-suite2");
    CHECK(to_hex(enc2) != to_hex(enc1));
    auto enc3 = config::encrypt(message1, key2, "test-suite1");
    CHECK(to_hex(enc3) != to_hex(enc1));
    auto nonce = enc1.substr(enc1.size() - 24);
    auto nonce2 = enc2.substr(enc2.size() - 24);
    auto nonce3 = enc3.substr(enc3.size() - 24);
    CHECK(to_hex(nonce) == "af2f4860cb4d0f8ba7e09d29e31f5e4a18f65847287a54a0");
    CHECK(to_hex(nonce2) == "277e639d36ba46470dfff509a68cb73d9a96386c51739bdd");
    CHECK(to_hex(nonce3) == to_hex(nonce));

    auto plain = config::decrypt(enc1, key1, "test-suite1");
    CHECK(plain == message1);
    CHECK_THROWS_AS(config::decrypt(enc1, key1, "test-suite2"), config::decrypt_error);
    CHECK_THROWS_AS(config::decrypt(enc1, key2, "test-suite1"), config::decrypt_error);

    enc1[3] = '\x42';
    CHECK_THROWS_AS(config::decrypt(enc1, key1, "test-suite1"), config::decrypt_error);
}

TEST_CASE("config message padding", "[config][padding]") {
    static_assert(config::padded_size(1, 0) == 256);
    static_assert(config::padded_size(1, 10) == 256 - 10);
    static_assert(config::padded_size(246, 10) == 256 - 10);
    static_assert(config::padded_size(247, 10) == 512 - 10);
    static_assert(config::padded_size(247, 10) == 512 - 10);
    static_assert(config::padded_size(247, 256) == 256);
    static_assert(config::padded_size(3839, 96) == 4000);
    static_assert(config::padded_size(1, 0) == 256);
    static_assert(config::padded_size(1, 10) == 256 - 10);
    static_assert(config::padded_size(246, 10) == 256 - 10);
    static_assert(config::padded_size(247, 10) == 512 - 10);
    static_assert(config::padded_size(247, 10) == 512 - 10);
    static_assert(config::padded_size(247, 256) == 256);
    static_assert(config::padded_size(3744, 96) == 3744);
    static_assert(config::padded_size(3745, 96) == 4000);
    static_assert(config::padded_size(4864, 0) == 4864);
    static_assert(config::padded_size(4865, 0) == 5_kiB);
    static_assert(config::padded_size(5_kiB + 1, 0) == 6_kiB);
    static_assert(config::padded_size(9_kiB, 0) == 9_kiB);
    static_assert(config::padded_size(9_kiB + 1, 0) == 10_kiB);
    static_assert(config::padded_size(10_kiB + 1, 0) == 11_kiB);
    static_assert(config::padded_size(20_kiB, 0) == 20_kiB);
    static_assert(config::padded_size(20_kiB + 1, 0) == 22_kiB);
    static_assert(config::padded_size(38_kiB, 0) == 38_kiB);
    static_assert(config::padded_size(38_kiB + 1, 0) == 40_kiB);
    static_assert(config::padded_size(40_kiB + 1, 0) == 45_kiB);
    static_assert(config::padded_size(45_kiB + 1, 0) == 50_kiB);
    static_assert(config::padded_size(70_kiB, 0) == 70_kiB);
    static_assert(config::padded_size(70_kiB + 1, 0) == 75_kiB);  // Coincides with max message size
    static_assert(config::padded_size(75_kiB, 0) == 75_kiB);      // Coincides with max message size
    static_assert(
            config::padded_size(75_kiB - 24, 24) ==
            75_kiB - 24);  // Coincides with max message size
    CHECK(true);
}

template <
        size_t N,
        typename RNG,
        std::enable_if_t<
                std::is_unsigned_v<typename RNG::result_type> && RNG::min() == 0u &&
                        RNG::max() == std::numeric_limits<typename RNG::result_type>::max() &&
                        N % sizeof(typename RNG::result_type) == 0,
                int> = 0>
std::array<unsigned char, N> random_bytes(RNG& rng) {

    std::array<unsigned char, N> result;
    for (size_t i = 0; i < N; i += sizeof(typename RNG::result_type))
        oxenc::write_host_as_little(rng(), &result[i]);

    return result;
}

struct Member {
    std::array<unsigned char, 32> seed;
    std::array<unsigned char, 64> ed25519_seckey;  // seed
    std::array<unsigned char, 32> ed25519_pubkey;  // M (not public)
    std::array<unsigned char, 32> x25519_pubkey;   // M' (AKA session id)
    std::array<unsigned char, 32> x25519_privkey;  // m priv key point (for both x and ed)

    template <typename RNG>
    explicit Member(RNG& rng) : seed{random_bytes<32>(rng)} {
        crypto_sign_seed_keypair(ed25519_pubkey.data(), ed25519_seckey.data(), seed.data());
        crypto_sign_ed25519_sk_to_curve25519(x25519_privkey.data(), ed25519_seckey.data());
        int rc = crypto_sign_ed25519_pk_to_curve25519(x25519_pubkey.data(), ed25519_pubkey.data());
        if (rc != 0)
            throw std::runtime_error{"Failed to convert Ed25519 pk to sk!"};
    }
};

const auto admin_hash_key = "SessionGroupKeyAdmin"_bytes;
const auto member_hash_key = "SessionGroupKeyMember"_bytes;

TEST_CASE("group key multi-encrypt", "[groups][encrypt][sodium]") {
    constexpr int member_size = 1000;

    // Not cryptographically secure, this is just for repeatable tests:
    std::mt19937_64 rng{123};

    Member admin{rng};

    std::vector<Member> members;
    for (int i = 0; i < member_size; i++)
        members.emplace_back(rng);

    auto new_group_key = random_bytes<32>(rng);

    CHECK(to_hex(admin.ed25519_pubkey) ==
          "98eaa614f3944e71db01b466ae734734c055c4a472b131f547ad2d9306f1c993");
    CHECK(to_hex(admin.ed25519_seckey) == to_hex(admin.seed) + to_hex(admin.ed25519_pubkey));
    CHECK(to_hex(members[456].ed25519_pubkey) ==
          "070f2719fc2749625d85c680ec7dd75fde662c070c4941e16501681ea1cd33a0");
    CHECK(to_hex(new_group_key) ==
          "40db04accf761600b492152b79d5073fe208629da2477aa295c6adea786fc5e3");

    bool first = true;
    using encrypted_key_t = std::array<
            unsigned char,
            std::tuple_size_v<decltype(new_group_key)> + crypto_aead_xchacha20poly1305_ietf_ABYTES>;
    static_assert(std::tuple_size_v<encrypted_key_t> == 48);

    std::vector<encrypted_key_t> member_enc_keys;
    member_enc_keys.reserve(members.size());

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;

    BENCHMARK("1000-member key encryption") {
        // Admin's point of view: need to encrypt `new_group_key` for each member.  For encryption
        // key we use:
        //
        // H(aM' || A' || M'), H = blake2b 32-byte hash with key "SessionGroupKeyMember"
        //
        // where the M'/A' are the X25519 conversions of the M/A Ed25519 pubkeys.  (Ideally we'd use
        // H(aM||A||M), but because of a historical mistake the Session idea is M', not M).
        //
        // We also encrypt for the admin (so that we only need to include decryption keys for
        // non-admins), but that uses a completely different key of:
        //
        // H(aA || A); H = blake2b 32-byte hash with key "SessionGroupKeyAdmin".  Note that aA is an
        // Ed25519 computation, not an X25519 computation (unlike the member key computation above).

        nonce = random_bytes<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>(rng);

        std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> enc_key;

        std::array<unsigned char, crypto_core_ed25519_BYTES> aA;
        int rc = crypto_scalarmult_ed25519(
                aA.data(), admin.x25519_privkey.data(), admin.ed25519_pubkey.data());
        REQUIRE(rc == 0);

        crypto_generichash_blake2b_state s;
        crypto_generichash_blake2b_init(
                &s, admin_hash_key.data(), admin_hash_key.size(), enc_key.size());
        crypto_generichash_blake2b_update(&s, aA.data(), aA.size());
        crypto_generichash_blake2b_update(
                &s, admin.ed25519_pubkey.data(), admin.ed25519_pubkey.size());
        crypto_generichash_blake2b_final(&s, enc_key.data(), enc_key.size());

        encrypted_key_t encrypted_key_admin;
        unsigned long long cipher_len;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
                encrypted_key_admin.data(),
                &cipher_len,
                new_group_key.data(),
                new_group_key.size(),
                nullptr,
                0,
                nullptr,
                nonce.data(),
                enc_key.data());
        REQUIRE(cipher_len == encrypted_key_admin.size());

        if (first)
            CHECK(to_hex(encrypted_key_admin) ==
                  "c86ef126c1aa90183b6b577a996d100c71a3b759bd3e67acb743457e9c3c1151"
                  "d83da75d00f7e13bd326f602898d868a");

        member_enc_keys.clear();
        for (auto& m : members) {
            crypto_generichash_blake2b_init(
                    &s, member_hash_key.data(), member_hash_key.size(), enc_key.size());

            std::array<unsigned char, crypto_scalarmult_BYTES> aM;
            rc = crypto_scalarmult(aM.data(), admin.x25519_privkey.data(), m.x25519_pubkey.data());
            REQUIRE(rc == 0);

            crypto_generichash_blake2b_update(&s, aM.data(), aM.size());
            crypto_generichash_blake2b_update(
                    &s, admin.x25519_pubkey.data(), admin.x25519_pubkey.size());
            crypto_generichash_blake2b_update(&s, m.x25519_pubkey.data(), m.x25519_pubkey.size());
            crypto_generichash_blake2b_final(&s, enc_key.data(), enc_key.size());

            auto& mek = member_enc_keys.emplace_back();
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                    mek.data(),
                    &cipher_len,
                    new_group_key.data(),
                    new_group_key.size(),
                    nullptr,
                    0,
                    nullptr,
                    nonce.data(),
                    enc_key.data());
            REQUIRE(cipher_len == mek.size());
        }

        if (first) {
            CHECK(to_hex(member_enc_keys[123]) ==
                  "a94fb549031e99598a73eab6f22895a29405aa8e980c744960b8809ca33aaa99"
                  "a933fdcbc89cd515f362427b3002160b");
            CHECK(to_hex(member_enc_keys[456]) ==
                  "13ad9040c13123ad778976f434f387edad17eb353ec283c92f349bdbd5886878"
                  "f2ecc1242b6b00a344ecec29c81f5f2c");
            CHECK(to_hex(member_enc_keys[789]) ==
                  "433485ceb0346abc72a8229689fff34241f4be9be8077103738cd595a420f4c4"
                  "5719a6f0a200f6248f8f89c2552cc4fc");
            first = false;
        }
    };

    // NB: this benchmark isn't the same as the above: this is timing how long it takes to attempt
    // to decrypt all 1000 member keys for each of the 1000 members.  Thus *one* member decryption
    // is 1/1000th of the benchmark time here.
    BENCHMARK("1000-member key decryption (x1000)") {
        std::uniform_int_distribution<size_t> rand_member_index{0, members.size()};
        auto& member = members[rand_member_index(rng)];

        crypto_generichash_blake2b_state s;
        for (const auto& member : members) {
            std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> dec_key;
            crypto_generichash_blake2b_init(
                    &s, member_hash_key.data(), member_hash_key.size(), dec_key.size());

            std::array<unsigned char, crypto_scalarmult_BYTES> mA;
            int rc = crypto_scalarmult(
                    mA.data(), member.x25519_privkey.data(), admin.x25519_pubkey.data());
            REQUIRE(rc == 0);

            crypto_generichash_blake2b_update(&s, mA.data(), mA.size());
            crypto_generichash_blake2b_update(
                    &s, admin.x25519_pubkey.data(), admin.x25519_pubkey.size());
            crypto_generichash_blake2b_update(
                    &s, member.x25519_pubkey.data(), member.x25519_pubkey.size());
            crypto_generichash_blake2b_final(&s, dec_key.data(), dec_key.size());

            // Now we have our dec_key, so iterate through all the encrypted keys and count how many
            // we successfully decrypt.  (We try them all, even after a success, for the test suite
            // but in production use we'd stop after a success).
            int successes = 0, failures = 0;
            std::array<unsigned char, 32> new_key;
            static_assert(
                    std::tuple_size_v<encrypted_key_t> ==
                    std::tuple_size_v<decltype(new_key)> +
                            crypto_aead_xchacha20poly1305_ietf_ABYTES);

            for (const auto& cipherkey : member_enc_keys) {
                unsigned long long plainlen;
                rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
                        new_key.data(),
                        &plainlen,
                        nullptr,
                        cipherkey.data(),
                        cipherkey.size(),
                        nullptr,
                        0,
                        nonce.data(),
                        dec_key.data());
                if (rc == 0) {
                    successes++;
                    REQUIRE(plainlen == new_key.size());
                    CHECK(to_hex(new_key) == to_hex(new_group_key));
                } else {
                    failures++;
                }
            }
            CHECK(successes == 1);
            CHECK(failures == members.size() - 1);
        }
    };
}

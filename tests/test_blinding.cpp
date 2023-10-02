
#include <oxenc/hex.h>
#include <sodium.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>

#include "session/blinding.hpp"
#include "session/util.hpp"

using namespace std::literals;
using namespace session;

constexpr std::array<unsigned char, 64> seed1{
        0xfe, 0xcd, 0x9a, 0x60, 0x34, 0xbc, 0x9a, 0xba, 0x27, 0x39, 0x25, 0xde, 0xe7,
        0x06, 0x2b, 0x12, 0x33, 0x34, 0x58, 0x7c, 0x3c, 0x62, 0x57, 0x34, 0x1a, 0xfa,
        0xe2, 0xd7, 0xfe, 0x85, 0xe1, 0x22, 0xf4, 0xef, 0x87, 0x39, 0x08, 0xf6, 0xa5,
        0x37, 0x7b, 0xa3, 0x85, 0x3f, 0x0e, 0x2f, 0xa3, 0x26, 0xee, 0xd9, 0xe7, 0x41,
        0xed, 0xf9, 0xf7, 0xd0, 0x31, 0x1a, 0x3e, 0xcc, 0x66, 0xa5, 0x7b, 0x32};
constexpr std::array<unsigned char, 64> seed2{
        0x86, 0x59, 0xef, 0xdc, 0xbe, 0x09, 0x49, 0xe0, 0xf8, 0x11, 0x41, 0xe6, 0xd3,
        0x97, 0xe8, 0xbe, 0x75, 0xf4, 0x5d, 0x09, 0x26, 0x2f, 0x20, 0x9d, 0x59, 0x50,
        0xe9, 0x79, 0x89, 0xeb, 0x43, 0xc7, 0x35, 0x70, 0xb6, 0x9a, 0x47, 0xdc, 0x09,
        0x45, 0x44, 0xc1, 0xc5, 0x08, 0x9c, 0x40, 0x41, 0x4b, 0xbd, 0xa1, 0xff, 0xdd,
        0xe8, 0xaa, 0xb2, 0x61, 0x7f, 0xe9, 0x37, 0xee, 0x74, 0xa5, 0xee, 0x81};

constexpr ustring_view pub1{seed1.data() + 32, 32};
constexpr ustring_view pub2{seed2.data() + 32, 32};

constexpr std::array<unsigned char, 32> xpub1{
        0xfe, 0x94, 0xb7, 0xad, 0x4b, 0x7f, 0x1c, 0xc1, 0xbb, 0x92, 0x67,
        0x1f, 0x1f, 0x0d, 0x24, 0x3f, 0x22, 0x6e, 0x11, 0x5b, 0x33, 0x77,
        0x04, 0x65, 0xe8, 0x2b, 0x50, 0x3f, 0xc3, 0xe9, 0x6e, 0x1f,
};
constexpr std::array<unsigned char, 32> xpub2{
        0x05, 0xc9, 0xa9, 0xbf, 0x17, 0x8f, 0xa6, 0x44, 0xd4, 0x4b, 0xeb,
        0xf6, 0x28, 0x71, 0x6d, 0xc7, 0xf2, 0xdf, 0x3d, 0x08, 0x42, 0xe9,
        0x78, 0x81, 0x96, 0x2c, 0x72, 0x36, 0x99, 0x15, 0x20, 0x73,
};

constexpr std::array<unsigned char, 32> pub2_abs{
        0x35, 0x70, 0xb6, 0x9a, 0x47, 0xdc, 0x09, 0x45, 0x44, 0xc1, 0xc5,
        0x08, 0x9c, 0x40, 0x41, 0x4b, 0xbd, 0xa1, 0xff, 0xdd, 0xe8, 0xaa,
        0xb2, 0x61, 0x7f, 0xe9, 0x37, 0xee, 0x74, 0xa5, 0xee, 0x01,
};

const std::string session_id1 = "05" + oxenc::to_hex(xpub1.begin(), xpub1.end());
const std::string session_id2 = "05" + oxenc::to_hex(xpub2.begin(), xpub2.end());

TEST_CASE("Communities 25xxx-blinded pubkey derivation", "[blinding25][pubkey]") {
    REQUIRE(sodium_init() >= 0);

    CHECK(blind25_id(
                  session_id1,
                  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") ==
          "253b991dcbba44cfdb45d5b38880d95cff723309e3ece6fd01415ad5fa1dccc7ac");
    CHECK(blind25_id(
                  session_id1,
                  "00cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") ==
          "2598589c7885b56cbeae6ab7b4224f202815520a54995872cb1833b44db6401c8d");
    CHECK(blind25_id(
                  session_id2,
                  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") ==
          "25a69cc6884530bf8498d22892e563716c4742f2845a7eb608de2aecbe7b6b5996");
}

template <size_t N>
ustring_view to_usv(const std::array<unsigned char, N>& val) {
    return {val.data(), N};
}

TEST_CASE("Communities 25xxx-blinded signing", "[blinding25][sign]") {

    std::array server_pks = {
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"sv,
            "00cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"sv,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"sv,
            "999def0123456789abcdef0123456789abcdef0123456789abcdef0123456789"sv,
            "888def0123456789abcdef0123456789abcdef0123456789abcdef0123456789"sv,
            "777def0123456789abcdef0123456789abcdef0123456789abcdef0123456789"sv};
    auto b25_1 = blind25_id(session_id1, server_pks[0]);
    auto b25_2 = blind25_id(session_id1, server_pks[1]);
    auto b25_3 = blind25_id(session_id2, server_pks[2]);
    auto b25_4 = blind25_id(session_id2, server_pks[3]);
    auto b25_5 = blind25_id(session_id2, server_pks[4]);
    auto b25_6 = blind25_id(session_id1, server_pks[5]);

    auto sig1 = blind25_sign(to_usv(seed1), server_pks[0], to_unsigned_sv("hello"));
    CHECK(oxenc::to_hex(sig1) ==
          "e6c57de4ac0cd278abbeef815bd88b163a037085deae789ecaaf4805884c4c3d3db25f3afa856241366cb341"
          "a3a4c9bbaa2cda81d028079c956fab16a7fe6206");
    CHECK(0 == crypto_sign_verify_detached(
                       sig1.data(),
                       to_unsigned("hello"),
                       5,
                       to_unsigned(oxenc::from_hex(b25_1).data()) + 1));

    auto sig2 = blind25_sign(to_usv(seed1), server_pks[1], to_unsigned_sv("world"));
    CHECK(oxenc::to_hex(sig2) ==
          "4460b606e9f55a7cba0bbe24207fe2859c3422783373788b6b070b2fa62ceba4f2a50749a6cee68e095747a3"
          "69927f9f4afa86edaf055cad68110e35e8b06607");
    CHECK(0 == crypto_sign_verify_detached(
                       sig2.data(),
                       to_unsigned("world"),
                       5,
                       to_unsigned(oxenc::from_hex(b25_2).data()) + 1));

    auto sig3 = blind25_sign(to_usv(seed2), server_pks[2], to_unsigned_sv("this"));
    CHECK(oxenc::to_hex(sig3) ==
          "57bb2f80c88ce2f677902ee58e02cbd83e4e1ec9e06e1c72a34b4ab76d0f5219cfd141ac5ce7016c73c8382d"
          "b99df9f317f2bc0af6ca68edac2a9a7670938902");
    CHECK(0 == crypto_sign_verify_detached(
                       sig3.data(),
                       to_unsigned("this"),
                       4,
                       to_unsigned(oxenc::from_hex(b25_3).data()) + 1));

    auto sig4 = blind25_sign(to_usv(seed2), server_pks[3], to_unsigned_sv("is"));
    CHECK(oxenc::to_hex(sig4) ==
          "ecce032b27b09d2d3d6df4ebab8cae86656c64fd1e3e70d6f020cd7e1a8058c57e3df7b6b01e90ccd592ac4a"
          "845dde7a2fdceb1a328a6690686851583133ea0c");
    CHECK(0 == crypto_sign_verify_detached(
                       sig4.data(),
                       to_unsigned("is"),
                       2,
                       to_unsigned(oxenc::from_hex(b25_4).data()) + 1));

    auto sig5 = blind25_sign(to_usv(seed2), server_pks[4], to_unsigned_sv(""));
    CHECK(oxenc::to_hex(sig5) ==
          "bf2fb9a511adbf5827e2e3bcf09f0a1cff80f85556fb76d8001aa8483b5f22e14539b170eaa0dbfa1489d1b8"
          "618ce8b48d7512cb5602c7eb8a05ce330a68350b");
    CHECK(0 ==
          crypto_sign_verify_detached(
                  sig5.data(), to_unsigned(""), 0, to_unsigned(oxenc::from_hex(b25_5).data()) + 1));

    auto sig6 = blind25_sign(to_usv(seed1), server_pks[5], to_unsigned_sv("omg!"));
    CHECK(oxenc::to_hex(sig6) ==
          "322e280fbc3547c6b6512dbea4d60563d32acaa2df10d665c40a336c99fc3b8e4b13a7109dfdeadab2ab58b2"
          "cb314eb0510b947f43e5dfb6e0ce5bf1499d240f");
    CHECK(0 == crypto_sign_verify_detached(
                       sig6.data(),
                       to_unsigned("omg!"),
                       4,
                       to_unsigned(oxenc::from_hex(b25_6).data()) + 1));

    // Test that it works when given just the seed instead of the whole sk:
    auto sig6b = blind25_sign(to_usv(seed1).substr(0, 32), server_pks[5], to_unsigned_sv("omg!"));
    CHECK(oxenc::to_hex(sig6b) ==
          "322e280fbc3547c6b6512dbea4d60563d32acaa2df10d665c40a336c99fc3b8e4b13a7109dfdeadab2ab58b2"
          "cb314eb0510b947f43e5dfb6e0ce5bf1499d240f");
    CHECK(0 == crypto_sign_verify_detached(
                       sig6b.data(),
                       to_unsigned("omg!"),
                       4,
                       to_unsigned(oxenc::from_hex(b25_6).data()) + 1));
}

#include <oxenc/hex.h>
#include <session/config/encrypt.h>
#include <session/config/user_profile.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

void log_msg(config_log_level lvl, const char* msg, void*) {
    INFO((lvl == LOG_LEVEL_ERROR     ? "ERROR"
          : lvl == LOG_LEVEL_WARNING ? "Warning"
          : lvl == LOG_LEVEL_INFO    ? "Info"
                                     : "debug")
         << ": " << msg);
}

TEST_CASE("user profile C API", "[config][user_profile][c]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed) == oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    // Initialize a brand new, empty config because we have no dump data to deal with.
    char err[256];
    config_object* conf;
    rc = user_profile_init(&conf, ed_sk.data(), NULL, 0, err);
    REQUIRE(rc == 0);

    config_set_logger(conf, log_msg, NULL);

    // We don't need to push anything, since this is an empty config
    CHECK_FALSE(config_needs_push(conf));
    // And we haven't changed anything so don't need to dump to db
    CHECK_FALSE(config_needs_dump(conf));

    // Since it's empty there shouldn't be a name.
    const char* name = user_profile_get_name(conf);
    CHECK(name == nullptr);  // (should be NULL instead of nullptr in C)

    unsigned char* to_push;
    size_t to_push_len;
    // We don't need to push since we haven't changed anything, so this call is mainly just for
    // testing:
    seqno_t seqno = config_push(conf, &to_push, &to_push_len);
    REQUIRE(to_push);
    CHECK(seqno == 0);
    const char* enc_domain = "UserProfile";
    REQUIRE(config_encryption_domain(conf) == std::string_view{enc_domain});
    size_t to_push_decr_size;
    unsigned char* to_push_decrypted =
            config_decrypt(to_push, to_push_len, ed_sk.data(), enc_domain, &to_push_decr_size);
    REQUIRE(to_push_decrypted);
    CHECK(to_push_decr_size == 256);
    CHECK(ustring_view{to_push_decrypted, to_push_decr_size} ==
          ustring(233, '\0') + "d1:#i0e1:&de1:<le1:=dee"_bytes);

    free(to_push);
    free(to_push_decrypted);

    // This should also be unset:
    auto pic = user_profile_get_pic(conf);
    CHECK(pic.url == nullptr);  // (should be NULL instead of nullptr in C)
    CHECK(pic.key == nullptr);  // (should be NULL instead of nullptr in C)
    CHECK(pic.keylen == 0);

    // Now let's go set a profile name and picture:
    CHECK(0 == user_profile_set_name(conf, "Kallie"));
    user_profile_pic p;
    p.url = "http://example.org/omg-pic-123.bmp";
    p.key = reinterpret_cast<const unsigned char*>("secretNOTSECRET");
    p.keylen = 6;
    CHECK(0 == user_profile_set_pic(conf, p));

    // Retrieve them just to make sure they set properly:
    name = user_profile_get_name(conf);
    REQUIRE(name != nullptr);  // (should be NULL instead of nullptr in C)
    CHECK(name == "Kallie"sv);

    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url);
    REQUIRE(pic.key);
    CHECK(pic.keylen == 6);
    CHECK(pic.url == "http://example.org/omg-pic-123.bmp"sv);
    CHECK(ustring_view{pic.key, pic.keylen} == "secret"_bytes);

    // Since we've made changes, we should need to push new config to the swarm, *and* should need
    // to dump the updated state:

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));
    seqno = config_push(conf, &to_push, &to_push_len);
    CHECK(seqno == 1);  // incremented since we made changes (this only increments once between
                        // dumps; even though we changed two fields here).

    // The hash of a completely empty, initial seqno=0 message:
    auto exp_hash0 = "ea173b57beca8af18c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c965"_hexbytes;

    // The data to be actually pushed, expanded like this to make it somewhat human-readable:
    // clang-format off
    auto exp_push1_decrypted =
        "d"
          "1:#" "i1e"
          "1:&" "d"
            "1:n" "6:Kallie"
            "1:p" "34:http://example.org/omg-pic-123.bmp"
            "1:q" "6:secret"
          "e"
          "1:<" "l"
            "l" "i0e" "32:"_bytes + exp_hash0 + "de" "e"
          "e"
          "1:=" "d"
            "1:n" "0:"
            "1:p" "0:"
            "1:q" "0:"
          "e"
        "e"_bytes;
    // clang-format on
    auto exp_push1_encrypted =
            "18767b5bcc1e0696d94a46ffe6d1cece0339d9290a6ced97ee2279d9fe6f4f79d80a469369e498f96f403d"
            "2f21de54976dbe218af0e188c3e74e1a2f761cea186eb10bbd9aeebe8d5074b7eb41b4d2965db315cf56f7"
            "080b576113fc525da840193a2713a7f81dabbf76e98ea0f9b18e819128de4de6e6acff6b31fae0c4daf07d"
            "25fb7d8bff009e61307471485daaf5bb0a70bc5dfaf1cc7ec46bf389296d0f84950ef90f7e257cffdb5d1c"
            "c7bff654f607afe97a42b0d874fbf55a8d5d4444a7b5f223375aec764c1763b256ed2126104b2fb18e0759"
            "795f037671c7a3d8ee68be7c09345baf593bef17cc941da9536361b65ff107177eb4fa100c74ead77bd0cd"
            "567bf56325ecc73d8056fbdaec9d4b1323edc38c71174114197818d4a386dfb698d915c2c21d"_hexbytes;

    CHECK(oxenc::to_hex(to_push, to_push + to_push_len) == to_hex(exp_push1_encrypted));

    // Raw decryption doesn't unpad (i.e. the padding is part of the encrypted data)
    to_push_decrypted =
            config_decrypt(to_push, to_push_len, ed_sk.data(), enc_domain, &to_push_decr_size);
    CHECK(to_push_decr_size == 256);
    CHECK(printable(to_push_decrypted, to_push_decr_size) ==
          printable(ustring(256 - exp_push1_decrypted.size(), '\0') + exp_push1_decrypted));

    // config_push gives us back a buffer that we are required to free when done.  (Without this
    // we'd leak memory!)
    free(to_push);

    // We haven't dumped, so still need to dump:
    CHECK(config_needs_dump(conf));
    // We did call push, but we haven't confirmed it as stored yet, so this will still return true:
    CHECK(config_needs_push(conf));
    unsigned char* dump1;
    size_t dump1len;

    config_dump(conf, &dump1, &dump1len);
    // (in a real client we'd now store this to disk)

    CHECK_FALSE(config_needs_dump(conf));

    // clang-format off
    CHECK(printable(dump1, dump1len) == printable(
        "d"
          "1:!" "i2e"
          "1:$" + std::to_string(exp_push1_decrypted.size()) + ":" + std::string{to_sv(exp_push1_decrypted)} + ""
        "e"));
    // clang-format on
    free(dump1);  // done with the dump; don't leak!

    // So now imagine we got back confirmation from the swarm that the push has been stored:
    config_confirm_pushed(conf, seqno);

    CHECK_FALSE(config_needs_push(conf));
    CHECK(config_needs_dump(conf));  // The confirmation changes state, so this makes us need a dump
                                     // again.
    config_dump(conf, &dump1, &dump1len);
    free(dump1);  // just ignore it for the test (but always have to free it).
                  //
    CHECK_FALSE(config_needs_dump(conf));

    // Now we're going to set up a second, competing config object (in the real world this would be
    // another Session client somewhere).

    // Start with an empty config, as above:
    config_object* conf2;
    REQUIRE(user_profile_init(&conf2, ed_sk.data(), NULL, 0, err) == 0);
    config_set_logger(conf2, log_msg, NULL);
    CHECK_FALSE(config_needs_dump(conf2));

    // Now imagine we just pulled down the encrypted string from the swarm; we merge it into conf2:
    const unsigned char* merge_data[1];
    size_t merge_size[1];
    merge_data[0] = exp_push1_encrypted.data();
    merge_size[0] = exp_push1_encrypted.size();
    int accepted = config_merge(conf2, merge_data, merge_size, 1);
    REQUIRE(accepted == 1);

    // Our state has changed, so we need to dump:
    CHECK(config_needs_dump(conf2));
    unsigned char* dump2;
    size_t dump2len;
    config_dump(conf2, &dump2, &dump2len);
    // (store in db)
    free(dump2);
    CHECK_FALSE(config_needs_dump(conf2));

    // We *don't* need to push: even though we updated, all we did is update to the merged data (and
    // didn't have any sort of merge conflict needed):
    CHECK_FALSE(config_needs_push(conf2));

    // Now let's create a conflicting update:

    // Change the name on both clients:
    user_profile_set_name(conf, "Nibbler");
    user_profile_set_name(conf2, "Raz");

    // And, on conf2, we're also going to change the profile pic:
    p.url = "http://new.example.com/pic";
    p.key = reinterpret_cast<const unsigned char*>("qwert\0yuio");
    p.keylen = 10;
    user_profile_set_pic(conf2, p);

    // Both have changes, so push need a push
    CHECK(config_needs_push(conf));
    CHECK(config_needs_push(conf2));
    seqno = config_push(conf, &to_push, &to_push_len);
    CHECK(seqno == 2);  // incremented, since we made a field change

    unsigned char* to_push2;
    size_t to_push2_len;
    auto seqno2 = config_push(conf2, &to_push2, &to_push2_len);
    CHECK(seqno == 2);  // incremented, since we made a field change

    config_dump(conf, &dump1, &dump1len);
    config_dump(conf2, &dump2, &dump2len);
    // (store in db)
    free(dump1);
    free(dump2);

    // Since we set different things, we're going to get back different serialized data to be
    // pushed:
    CHECK(printable(to_push, to_push_len) != printable(to_push2, to_push2_len));

    // Now imagine that each client pushed its `seqno=2` config to the swarm, but then each client
    // also fetches new messages and pulls down the other client's `seqno=2` value.

    // Feed the new config into each other.  (This array could hold multiple configs if we pulled
    // down more than one).
    merge_data[0] = to_push;
    merge_size[0] = to_push_len;
    config_merge(conf2, merge_data, merge_size, 1);
    free(to_push);
    merge_data[0] = to_push2;
    merge_size[0] = to_push2_len;
    config_merge(conf, merge_data, merge_size, 1);
    free(to_push2);

    // Now after the merge we *will* want to push from both client, since both will have generated a
    // merge conflict update (with seqno = 3).
    CHECK(config_needs_push(conf));
    CHECK(config_needs_push(conf2));
    seqno = config_push(conf, &to_push, &to_push_len);
    seqno2 = config_push(conf2, &to_push2, &to_push2_len);

    CHECK(seqno == 3);
    CHECK(seqno2 == 3);

    // They should have resolved the conflict to the same thing:
    CHECK(user_profile_get_name(conf) == "Nibbler"sv);
    CHECK(user_profile_get_name(conf2) == "Nibbler"sv);
    // (Note that they could have also both resolved to "Raz" here, but the hash of the serialized
    // message just happens to have a higher hash -- and thus gets priority -- for this particular
    // test).

    // Since only one of them set a profile pic there should be no conflict there:
    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url);
    CHECK(pic.url == "http://new.example.com/pic"sv);
    REQUIRE(pic.key);
    CHECK(ustring_view{pic.key, pic.keylen} == "qwert\0yuio"_bytes);
    pic = user_profile_get_pic(conf2);
    REQUIRE(pic.url);
    CHECK(pic.url == "http://new.example.com/pic"sv);
    REQUIRE(pic.key);
    CHECK(ustring_view{pic.key, pic.keylen} == "qwert\0yuio"_bytes);

    config_confirm_pushed(conf, seqno);
    config_confirm_pushed(conf2, seqno2);

    config_dump(conf, &dump1, &dump1len);
    config_dump(conf2, &dump2, &dump2len);
    // (store in db)
    free(dump1);
    free(dump2);

    CHECK_FALSE(config_needs_dump(conf));
    CHECK_FALSE(config_needs_dump(conf2));
    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_push(conf2));
}

#include <oxenc/hex.h>
#include <session/config/encrypt.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <session/config/user_profile.hpp>
#include <session/util.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

void log_msg(session::config::LogLevel lvl, std::string msg) {
    INFO((lvl == session::config::LogLevel::error     ? "ERROR"
          : lvl == session::config::LogLevel::warning ? "Warning"
          : lvl == session::config::LogLevel::info    ? "Info"
                                                      : "debug")
         << ": " << msg);
}

TEST_CASE("user profile", "[config][user_profile]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
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

    session::config::UserProfile conf{ustring_view{seed}, std::nullopt};
    conf.logger = log_msg;

    // We don't need to push anything, since this is an empty config
    CHECK_FALSE(conf.needs_push());
    // And we haven't changed anything so don't need to dump to db
    CHECK_FALSE(conf.needs_dump());

    // Since it's empty there shouldn't be a name.
    auto name = conf.get_name();
    CHECK(name == std::nullopt);

    // We don't need to push since we haven't changed anything, so this call is mainly just for
    // testing:
    auto [seqno, to_push, obs] = conf.push();
    CHECK(seqno == 0);
    CHECK(to_push.size() == 256 + 176);  // 176 = protobuf overhead
    REQUIRE(conf.encryption_domain() == "UserProfile"sv);

    // There's nothing particularly profound about this value (it is multiple layers of nested
    // protobuf with some encryption and padding halfway through); this test is just here to ensure
    // that our pushed messages are deterministic:
    CHECK(oxenc::to_hex(to_push.begin(), to_push.end()) ==
          "080112ab030a0012001aa20308062801429b0326ec9746282053eb119228e6c36012966e7d2642163169ba39"
          "98af44ca65f967768dd78ee80fffab6f809f6cef49c73a36c82a89622ff0de2ceee06b8c638e2c876fa9047f"
          "449dbe24b1fc89281a264fe90abdeffcdd44f797bd4572a6c5ae8d88bf372c3c717943ebd570222206fabf0e"
          "e9f3c6756f5d71a32616b1df53d12887961f5c129207a79622ccc1a4bba976886d9a6ddf0fe5d570e5075d01"
          "ecd627f656e95f27b4c40d5661b5664cedd3e568206effa1308b0ccd663ca61a6d39c0731891804a8cf5edcf"
          "8b98eaa5580c3d436e22156e38455e403869700956c3c1dd0b4470b663e75c98c5b859b53ccef6559215d804"
          "9f755be9c2d6b3f4a310f97c496fc392f65b6431dd87788ac61074fd8cd409702e1b839b3f774d38cf8b28f0"
          "226c4efa5220ac6ae060793e36e7ef278d42d042f15b21291f3bb29e3158f09d154b93f83fd8a319811a26cb"
          "5240d90cbb360fafec0b7eff4c676ae598540813d062dc9468365c73b4cfa2ffd02d48cdcd8f0c71324c6d0a"
          "60346a7a0e50af3be64684b37f9e6c831115bf112ddd18acde08eaec376f0872a3952000");

    // These should also be unset:
    auto pic = conf.get_profile_pic();
    CHECK(pic.url.size() == 0);
    CHECK(conf.get_nts_priority() == 0);
    CHECK(conf.get_nts_expiry() == std::nullopt);

    // Now let's go set them:
    conf.set_name("Kallie");
    session::config::profile_pic p;
    {
        // These don't stay alive, so we use set_key/set_url to make a local copy:
        ustring key = "secret78901234567890123456789012"_bytes;
        std::string url =
                "http://example.org/omg-pic-123.bmp";  // NB: length must be < sizeof(p.url)!
        p.set_key(std::move(key));
        p.url = std::move(url);
    }
    conf.set_profile_pic(p);
    conf.set_nts_priority(9);

    // Retrieve them just to make sure they set properly:
    name = conf.get_name();
    REQUIRE(name != std::nullopt);
    CHECK(name == "Kallie"sv);

    pic = conf.get_profile_pic();
    REQUIRE(pic.url.size() > 0);
    REQUIRE(pic.key.size() > 0);
    CHECK(pic.url == "http://example.org/omg-pic-123.bmp");
    CHECK(pic.key == "secret78901234567890123456789012"_bytes);

    CHECK(conf.get_nts_priority() == 9);

    // Since we've made changes, we should need to push new config to the swarm, *and* should need
    // to dump the updated state:

    CHECK(conf.needs_push());
    CHECK(conf.needs_dump());
    std::tie(seqno, to_push, obs) = conf.push();
    CHECK(seqno == 1);  // incremented since we made changes (this only increments once
                        // between dumps; even though we changed two fields here).

    // The hash of a completely empty, initial seqno=0 message:
    auto exp_hash0 = "ea173b57beca8af18c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c965"_hexbytes;

    // The data to be actually pushed, expanded like this to make it somewhat human-readable:
    // clang-format off
    auto exp_push1_decrypted =
        "d"
          "1:#" "i1e"
          "1:&" "d"
            "1:+" "i9e"
            "1:n" "6:Kallie"
            "1:p" "34:http://example.org/omg-pic-123.bmp"
            "1:q" "32:secret78901234567890123456789012"
          "e"
          "1:<" "l"
            "l" "i0e" "32:"_bytes + exp_hash0 + "de" "e"
          "e"
          "1:=" "d"
            "1:+" "0:"
            "1:n" "0:"
            "1:p" "0:"
            "1:q" "0:"
          "e"
        "e"_bytes;
    // clang-format on
    auto exp_push1_encrypted =
            "9693a69686da3055f1ecdfb239c3bf8e746951a36d888c2fb7c02e856a5c2091b24e39a7e1af828f"
            "1fa09fe8bf7d274afde0a0847ba143c43ffb8722301b5ae32e2f078b9a5e19097403336e50b18c84"
            "aade446cd2823b011f97d6ad2116a53feb814efecc086bc172d31f4214b4d7c630b63bbe575b0868"
            "2d146da44915063a07a78556ab5eff4f67f6aa26211e8d330b53d28567a931028c393709a325425d"
            "e7486ccde24416a7fd4a8ba5fa73899c65f4276dfaddd5b2100adcf0f793104fb235b31ce32ec656"
            "056009a9ebf58d45d7d696b74e0c7ff0499c4d23204976f19561dc0dba6dc53a2497d28ce03498ea"
            "49bf122762d7bc1d6d9c02f6d54f8384"_hexbytes;

    // We haven't dumped, so still need to dump:
    CHECK(conf.needs_dump());
    // We did call push, but we haven't confirmed it as stored yet, so this will still return true:
    CHECK(conf.needs_push());

    auto dump1 = conf.dump();
    // (in a real client we'd now store this to disk)

    CHECK_FALSE(conf.needs_dump());

    // clang-format off
    CHECK(printable({dump1.data(), dump1.size()}) == printable(
        "d"
          "1:!" "i2e"
          "1:$" + std::to_string(exp_push1_decrypted.size()) + ":" + std::string{to_sv(exp_push1_decrypted)} + ""
          "1:(" "0:"
          "1:)" "le"
        "e"));
    // clang-format on

    // So now imagine we got back confirmation from the swarm that the push has been stored:
    conf.confirm_pushed(seqno, "fakehash1");

    CHECK_FALSE(conf.needs_push());
    CHECK(conf.needs_dump());  // The confirmation changes state, so this makes us need a dump
                               // again.
    dump1 = conf.dump();

    // clang-format off
    CHECK(printable({dump1.data(), dump1.size()}) == printable(
        "d"
          "1:!" "i0e"
          "1:$" + std::to_string(exp_push1_decrypted.size()) + ":" + std::string{to_sv(exp_push1_decrypted)} + ""
          "1:(" "9:fakehash1"
          "1:)" "le"
        "e"));
    // clang-format on

    CHECK_FALSE(conf.needs_dump());

    // Now we're going to set up a second, competing config object (in the real world this would be
    // another Session client somewhere).

    // Start with an empty config, as above:
    session::config::UserProfile conf2{ustring_view{seed}, std::nullopt};
    conf2.logger = log_msg;
    CHECK_FALSE(conf2.needs_dump());

    // Now imagine we just pulled down the encrypted string from the swarm; we merge it into conf2:
    std::vector<std::pair<std::string, ustring_view>> merge_configs;
    merge_configs.emplace_back("fakehash1", exp_push1_encrypted);
    auto accepted = conf2.merge(merge_configs);
    REQUIRE(accepted.size() == 1);
    CHECK(accepted[0] == "fakehash1"sv);

    // Our state has changed, so we need to dump:
    CHECK(conf2.needs_dump());
    auto dump2 = conf2.dump();
    // (store in db)
    CHECK_FALSE(conf2.needs_dump());

    // We *don't* need to push: even though we updated, all we did is update to the merged data (and
    // didn't have any sort of merge conflict needed):
    REQUIRE_FALSE(conf2.needs_push());

    // Now let's create a conflicting update:

    // Change the name on both clients:
    conf.set_name("Nibbler");
    conf2.set_name("Raz");

    // And, on conf2, we're also going to change some other things:
    ustring key2 = "qwert\0yuio1234567890123456789012"_bytes;
    std::string url2 = "http://new.example.com/pic";
    p.set_key(std::move(key2));
    p.url = std::move(url2);
    conf2.set_profile_pic(p);

    conf2.set_nts_expiry(86400s);
    CHECK(conf2.get_nts_expiry() == 86400s);

    CHECK(conf2.get_blinded_msgreqs() == std::nullopt);
    conf2.set_blinded_msgreqs(false);
    CHECK(conf2.get_blinded_msgreqs() == false);
    conf2.set_blinded_msgreqs(std::nullopt);
    CHECK(conf2.get_blinded_msgreqs() == std::nullopt);
    conf2.set_blinded_msgreqs(true);
    CHECK(conf2.get_blinded_msgreqs() == true);

    // Both have changes, so push need a push
    CHECK(conf.needs_push());
    CHECK(conf2.needs_push());
    std::tie(seqno, to_push, obs) = conf.push();
    CHECK(seqno == 2);  // incremented, since we made a field change
    conf.confirm_pushed(seqno, "fakehash2");

    auto [seqno2, to_push2, obs2] = conf2.push();
    CHECK(seqno2 == 2);  // incremented, since we made a field change
    conf2.confirm_pushed(seqno2, "fakehash3");

    dump1 = conf.dump();
    dump2 = conf2.dump();
    // (store in db)

    // Since we set different things, we're going to get back different serialized data to be
    // pushed:
    CHECK(printable({to_push.data(), to_push.size()}) !=
          printable({to_push2.data(), to_push2.size()}));

    // Now imagine that each client pushed its `seqno=2` config to the swarm, but then each client
    // also fetches new messages and pulls down the other client's `seqno=2` value.

    // Feed the new config into each other.  (This array could hold multiple configs if we pulled
    // down more than one).
    merge_configs[0] = {"fakehash2", to_push};
    accepted = conf2.merge(merge_configs);
    REQUIRE(accepted.size() == 1);
    CHECK(accepted[0] == "fakehash2"sv);

    merge_configs[0] = {"fakehash3", to_push2};
    accepted = conf.merge(merge_configs);
    REQUIRE(accepted.size() == 1);
    CHECK(accepted[0] == "fakehash3"sv);

    // Now after the merge we *will* want to push from both client, since both will have generated a
    // merge conflict update (with seqno = 3).
    std::tie(seqno, to_push, obs) = conf.push();
    std::tie(seqno2, to_push2, obs2) = conf2.push();

    REQUIRE(seqno == 3);
    REQUIRE(seqno2 == 3);
    REQUIRE(conf.needs_push());
    REQUIRE(conf2.needs_push());

    // They should have resolved the conflict to the same thing:
    CHECK(conf.get_name() == "Nibbler"sv);
    CHECK(conf2.get_name() == "Nibbler"sv);
    // (Note that they could have also both resolved to "Raz" here, but the hash of the serialized
    // message just happens to have a higher hash -- and thus gets priority -- for this particular
    // test).

    // Since only one of them set a profile pic there should be no conflict there:
    pic = conf.get_profile_pic();
    CHECK(pic.url == "http://new.example.com/pic"sv);
    CHECK(oxenc::to_hex(pic.key.begin(), pic.key.end()) ==
          "7177657274007975696f31323334353637383930313233343536373839303132");
    pic = conf2.get_profile_pic();
    CHECK(pic.url == "http://new.example.com/pic"sv);
    CHECK(oxenc::to_hex(pic.key.begin(), pic.key.end()) ==
          "7177657274007975696f31323334353637383930313233343536373839303132");

    CHECK(conf.get_nts_priority() == 9);
    CHECK(conf2.get_nts_priority() == 9);
    CHECK(conf.get_nts_expiry() == 86400s);
    CHECK(conf2.get_nts_expiry() == 86400s);
    CHECK(conf.get_blinded_msgreqs() == true);
    CHECK(conf2.get_blinded_msgreqs() == true);

    conf.confirm_pushed(seqno, "fakehash4");
    conf2.confirm_pushed(seqno2, "fakehash4");

    dump1 = conf.dump();
    dump2 = conf2.dump();
    // (store in db)

    CHECK_FALSE(conf.needs_dump());
    CHECK_FALSE(conf2.needs_dump());
    CHECK_FALSE(conf.needs_push());
    CHECK_FALSE(conf2.needs_push());
}

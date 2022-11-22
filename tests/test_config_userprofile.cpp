#include <oxenc/hex.h>
#include <session/config/user_profile.h>

#include <catch2/catch_test_macros.hpp>
#include <string_view>

using namespace std::literals;
using namespace oxenc::literals;

namespace {

std::string printable(std::string_view x) {
    std::string p;
    for (auto c : x) {
        if (c >= 0x20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}
std::string printable(const char* x) = delete;
std::string printable(const char* x, size_t n) {
    return printable({x, n});
}

}  // namespace

TEST_CASE("user profile C API", "[config][user_profile][c]") {

    char err[256];
    config_object* conf;
    int rc = user_profile_init(&conf, NULL, 0, err);
    REQUIRE(rc == 0);

    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_dump(conf));

    const char* name = user_profile_get_name(conf);
    CHECK(name == NULL);

    char* to_push;
    size_t to_push_len;
    seqno_t seqno = config_push(conf, &to_push, &to_push_len);
    REQUIRE(to_push);
    CHECK(seqno == 0);
    CHECK(to_push == "d1:#i0e1:&de1:<le1:=dee"sv);
    free(to_push);

    auto pic = user_profile_get_pic(conf);
    CHECK_FALSE(pic.url);
    CHECK_FALSE(pic.key);
    CHECK(pic.keylen == 0);

    CHECK( 0 == user_profile_set_name(conf, "Kallie") );
    user_profile_pic p;
    p.url = "http://example.org/omg-pic-123.bmp";
    p.key = "secretNOTSECRET";
    p.keylen = 6;
    CHECK( 0 == user_profile_set_pic(conf, p) );

    name = user_profile_get_name(conf);
    REQUIRE(name != NULL);
    CHECK(name == "Kallie"sv);

    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url);
    REQUIRE(pic.key);
    CHECK(pic.keylen == 6);
    CHECK(pic.url == "http://example.org/omg-pic-123.bmp"sv);
    CHECK(std::string_view{pic.key, pic.keylen} == "secret");

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));
    seqno = config_push(conf, &to_push, &to_push_len);
    CHECK(seqno == 1);
    auto exp_hash0 = "ea173b57beca8af18c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c965"_hex;
    // clang-format off
    auto exp_push1 = 
        "d"
          "1:#" "i1e"
          "1:&" "d"
            "1:n" "6:Kallie"
            "1:p" "34:http://example.org/omg-pic-123.bmp"
            "1:q" "6:secret"
          "e"
          "1:<" "l"
            "l" "i0e" "32:" + exp_hash0 + "de" "e"
          "e"
          "1:=" "d"
            "1:n" "0:"
            "1:p" "0:"
            "1:q" "0:"
          "e"
        "e";
    // clang-format on
    CHECK(printable(to_push, to_push_len) == printable(exp_push1));
    free(to_push);

    CHECK(config_needs_dump(conf));
    CHECK(config_needs_push(conf));
    char* dump1;
    size_t dump1len;
    config_dump(conf, &dump1, &dump1len);

    CHECK_FALSE(config_needs_dump(conf));

    // clang-format off
    CHECK(printable(dump1, dump1len) == printable(
        "d"
          "1:!" "i2e"
          "1:$" + std::to_string(exp_push1.size()) + ":" + exp_push1 + ""
        "e"));

    confirm_pushed(conf, seqno);

    CHECK_FALSE(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    // Load the config into a competing config object:
    config_object* conf2;
    REQUIRE(user_profile_init(&conf2, NULL, 0, err) == 0);
    CHECK_FALSE(config_needs_dump(conf2));
    const char* merge_data[1];
    size_t merge_size[1];
    merge_data[0] = exp_push1.c_str();
    merge_size[0] = exp_push1.size();
    config_merge(conf2, merge_data, merge_size, 1);
    CHECK(config_needs_dump(conf2));
    CHECK_FALSE(config_needs_push(conf2));

    // Oh no, conflict!
    user_profile_set_name(conf, "Nibbler");
    user_profile_set_name(conf2, "Raz");
    // And also another, non-conflicting change:
    p.url = "http://new.example.com/pic";
    p.key = "qwert\0yuio";
    p.keylen = 10;
    user_profile_set_pic(conf2, p);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_push(conf2));
    seqno = config_push(conf, &to_push, &to_push_len);
    CHECK(seqno == 2);

    char* to_push2;
    size_t to_push2_len;
    auto seqno2 = config_push(conf2, &to_push2, &to_push2_len);
    CHECK(seqno == 2);

    CHECK(printable(to_push, to_push_len) != printable(to_push2, to_push2_len));

    // Merge each others changes into each one:
    merge_data[0] = to_push;
    merge_size[0] = to_push_len;
    config_merge(conf2, merge_data, merge_size, 1);
    merge_data[0] = to_push2;
    merge_size[0] = to_push2_len;
    config_merge(conf, merge_data, merge_size, 1);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_push(conf2));
    free(to_push);
    seqno = config_push(conf, &to_push, &to_push_len);
    free(to_push2);
    seqno2 = config_push(conf2, &to_push2, &to_push2_len);

    // They should have resolved to the same thing:
    CHECK(user_profile_get_name(conf) == "Nibbler"sv);
    CHECK(user_profile_get_name(conf2) == "Nibbler"sv);
    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url);
    CHECK(pic.url == "http://new.example.com/pic"sv);
    REQUIRE(pic.key);
    CHECK(std::string_view{pic.key, pic.keylen} == "qwert\0yuio"sv);
    pic = user_profile_get_pic(conf2);
    REQUIRE(pic.url);
    CHECK(pic.url == "http://new.example.com/pic"sv);
    REQUIRE(pic.key);
    CHECK(std::string_view{pic.key, pic.keylen} == "qwert\0yuio"sv);
}

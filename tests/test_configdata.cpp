#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign.h>

#include <catch2/catch_test_macros.hpp>
#include <session/config.hpp>

#include "session/bt_merge.hpp"

using namespace session;
using namespace std::literals;
using oxenc::bt_dict;
using oxenc::bt_list;

TEST_CASE("config data scalar encoding", "[config][data][scalar]") {
    CHECK(oxenc::bt_serialize(config::scalar{3}) == "i3e");
    CHECK(oxenc::bt_serialize(config::scalar{"hi"}) == "2:hi");
    CHECK(oxenc::bt_serialize(config::scalar{-42}) == "i-42e");
}
TEST_CASE("config data set encoding", "[config][data][set]") {
    config::set s;
    s.insert("foo");
    s.insert(23);
    s.insert("Foo");
    s.insert("~");
    s.insert("!");
    s.insert("foo");  // dupe
    s.insert(-123);

    CHECK(oxenc::bt_serialize(s) == "li-123ei23e1:!3:Foo3:foo1:~e");
}

TEST_CASE("config data dict encoding", "[config][data][dict]") {
    config::dict d;
    d["a"] = 23;
    d["B"] = "x";
    d["c"] = config::set{{"2", "1", 4, -3}};
    d["D"] = config::dict{{"x", 1}, {"y", 2}};
    d["d"] = config::dict{{"e", config::dict{{"f", config::dict{{"g", ""}}}}}};

    CHECK(oxenc::bt_serialize(d) ==
          "d1:B1:x1:Dd1:xi1e1:yi2ee1:ai23e1:cli-3ei4e1:11:2e1:dd1:ed1:fd1:g0:eeee");
}

TEST_CASE("config pruning", "[config][prune]") {
    config::ConfigMessage m;
    m.data["a"] = 123;

    CHECK(m.data == config::dict{{"a", 123}});

    m.prune();
    CHECK(m.data == config::dict{{"a", 123}});

    m.data["b"] = config::dict{};
    m.prune();
    CHECK(m.data.size() == 1);
    CHECK(m.data == config::dict{{"a", 123}});

    m.data["b"] = config::dict{};
    m.data["c"] = config::dict{{"a", 1}};
    m.data["d"] = config::set{{42}};
    m.data["e"] = config::set{};
    m.prune();
    CHECK(m.data.size() == 3);
    CHECK(m.data ==
          config::dict{{"a", 123}, {"c", config::dict{{"a", 1}}}, {"d", config::set{{42}}}});

    m.data["b"] = config::dict{};
    m.data["e"] = config::set{};
    m.data["f"] = config::dict{{"a", 1}, {"b", config::set{}}};
    m.data["g"] = config::dict{{"a", config::dict{{"a", config::dict{{"a", config::dict{}}}}}}};

    CHECK(m.data.size() == 7);
    m.prune();
    CHECK(m.data.size() == 4);
    CHECK(m.data == config::dict{
                            {"a", 123},
                            {"c", config::dict{{"a", 1}}},
                            {"d", config::set{{42}}},
                            {"f", config::dict{{"a", 1}}},
                    });
}

// shortcut to access a nested dict
auto& d(config::dict_value& v) {
    return var::get<config::dict>(v);
}
// or set
auto& s(config::dict_value& v) {
    return var::get<config::set>(v);
}

template <typename T, size_t N>
std::string_view view(const std::array<T, N>& data) {
    return std::string_view{reinterpret_cast<const char*>(data.data()), data.size()};
}
template <typename T, size_t N>
std::string view_hex(const std::array<T, N>& data) {
    return oxenc::to_hex(data.begin(), data.end());
}

std::string printable(std::string_view x) {
    std::string p;
    for (auto c : x) {
        if (c >= 20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}

TEST_CASE("config diff", "[config][diff]") {
    config::ConfigMessage m;
    m.data["foo"] = 123;
    m.data["empty"] = config::set{};
    m.data["empty2"] = config::dict{};
    m.data["bar"] = config::dict{{"asdf", 123}, {"xyz", "abc"}, {"", config::set{{"a", "b", 42}}}};
    m.data["z"];  // will autovivify as a dict, but empty so will get pruned

    CHECK(m.seqno == 0);
    auto diff = m.diff();
    CHECK(diff.size() == 2);
    CHECK(diff == bt_dict{{"foo", ""sv},
                          {"bar",
                           bt_dict{{"asdf", ""sv},
                                   {"xyz", ""sv},
                                   {"", bt_list{{bt_list{{42, "a"s, "b"s}}, bt_list{}}}}}}});

    auto m1 = m.increment();
    CHECK(m1.seqno == 1);
    CHECK(m1.diff().empty());
    m1.data.erase("foo");

    diff = m1.diff();
    CHECK(diff.size() == 1);
    CHECK(diff == bt_dict{{"foo", "-"sv}});

    auto m2 = m1.increment();
    CHECK(m2.seqno == 2);
    CHECK(m2.diff().empty());

    m2.data["foo"] = 123;
    d(m2.data["bar"])["xyz"] = 42;
    d(m2.data["bar"])["a"] = 42;
    s(d(m2.data["bar"])[""]).insert("c");
    s(d(m2.data["bar"])[""]).insert(99);
    s(d(m2.data["bar"])[""]).erase("b");
    s(d(m2.data["bar"])[""]).insert(42);  // already present

    diff = m2.diff();
    CHECK(diff.size() == 2);
    CHECK(diff == bt_dict{{"foo", ""sv},
                          {"bar",
                           bt_dict{{"xyz", ""sv},
                                   {"a", ""sv},
                                   {"", bt_list{{bt_list{{99, "c"s}}, bt_list{{"b"s}}}}}}}});
}

TEST_CASE("config message serialization", "[config][serialization]") {
    config::ConfigMessage m;
    m.seqno = 10;
    m.data["foo"] = 123;
    m.data["bar"] = config::dict{{"asdf", 123}, {"xyz", "abc"}, {"", config::set{{"a", "b", 42}}}};

    // clang-format off
    CHECK(printable(m.serialize()) == printable(
        "d"
          "1:#" "i10e"
          "1:&" "d"
            "3:bar" "d"
              "0:" "li42e1:a1:be"
              "4:asdf" "i123e"
              "3:xyz" "3:abc"
            "e"
            "3:foo" "i123e"
          "e"
          "1:<" "le"
          "1:=" "d"
            "3:bar" "d"
              "0:" "lli42e1:a1:belee"
              "4:asdf" "0:"
              "3:xyz" "0:"
            "e"
            "3:foo" "0:"
          "e"
        "e"));
    // clang-format on

    const auto hash0 = "d65738bba88b0f3455cef20fe09a7b4b10f25f9db82be24a6ce1bd06da197526";
    CHECK(view_hex(m.hash()) == hash0);

    auto m1 = m.increment();
    m1.data.erase("foo");
    const auto hash1 = "5b30b4abf4cba71db25dbc0d977cc25df1d0a8a87cad7f561cdec2b8caf65f5e";
    CHECK(view_hex(m1.hash()) == hash1);

    auto m2 = m1.increment();

    m2.data["foo"] = 123;
    d(m2.data["bar"])["xyz"] = 42;
    d(m2.data["bar"])["a"] = 42;
    s(d(m2.data["bar"])[""]).insert("c");
    s(d(m2.data["bar"])[""]).insert(99);
    s(d(m2.data["bar"])[""]).erase("b");
    s(d(m2.data["bar"])[""]).insert(42);  // already present

    const auto hash2 = "027552203cf669070d3ecbeecfa65c65497d59aa4da490e0f68f8131ce081320";
    CHECK(view_hex(m2.hash()) == hash2);

    // clang-format off
    CHECK(printable(m2.serialize()) == printable(
        "d"
          "1:#" "i12e"
          "1:&" "d"
            "3:bar" "d"
              "0:" "li42ei99e1:a1:ce"
              "1:a" "i42e"
              "4:asdf" "i123e"
              "3:xyz" "i42e"
            "e"
            "3:foo" "i123e"
          "e"
          "1:<" "l"
            "l"
              "i10e"
              "32:" + oxenc::from_hex(hash0) +
              "d"
                "3:bar" "d"
                  "0:" "lli42e1:a1:belee"
                  "4:asdf" "0:"
                  "3:xyz" "0:"
                "e"
                "3:foo" "0:"
              "e"
            "e"
            "l"
              "i11e"
              "32:" + oxenc::from_hex(hash1) +
              "d"
                "3:foo" "1:-"
              "e"
            "e"
          "e"
          "1:=" "d"
            "3:bar" "d"
              "0:" "l" "li99e1:ce" "l1:be" "e"
              "1:a" "0:"
              "3:xyz" "0:"
            "e"
            "3:foo" "0:"
          "e"
        "e"));

    auto m5 = m2.increment().increment().increment();
    const auto hash3 = "b83871ea06587f9254cdf2b2af8daff19bd7fb550fb90d5f8f9f546464c08bc5";
    const auto hash4 = "c30e2cfa7ec93c64a1ab6420c9bccfb63da8e4c2940ed6509ffb64f3f0131860";
    const auto hash5 = "3234eb7da8cf4b79b9eec2a144247279d10f6f118184f82429a42c5996bea60c";

    CHECK(view_hex(m2.increment().hash()) == hash3);
    CHECK(view_hex(m2.increment().increment().hash()) == hash4);
    CHECK(view_hex(m5.hash()) == hash5);

    CHECK(printable(m5.serialize()) == printable(
        "d"
          "1:#" "i15e"
          "1:&" "d"
            "3:bar" "d"
              "0:" "li42ei99e1:a1:ce"
              "1:a" "i42e"
              "4:asdf" "i123e"
              "3:xyz" "i42e"
            "e"
            "3:foo" "i123e"
          "e"
          "1:<" "l"
            "l"
              "i11e"
              "32:" + oxenc::from_hex(hash1) +
              "d"
                "3:foo" "1:-"
              "e"
            "e"
            "l"
              "i12e"
              "32:" + oxenc::from_hex(hash2) +
              "d"
                "3:bar" "d"
                  "0:" "l" "li99e1:ce" "l1:be" "e"
                  "1:a" "0:"
                  "3:xyz" "0:"
                "e"
                "3:foo" "0:"
              "e"
            "e"
            "l"
              "i13e"
              "32:" + oxenc::from_hex(hash3) +
              "de"
            "e"
            "l"
              "i14e"
              "32:" + oxenc::from_hex(hash4) +
              "de"
            "e"
          "e"
          "1:=" "d"
          "e"
        "e"));

    // clang-format on
}

TEST_CASE("config message signature", "[config][signing]") {
    config::ConfigMessage m;
    m.seqno = 10;
    m.data["foo"] = 123;
    m.data["bar"] = config::dict{{"asdf", 123}, {"xyz", "abc"}, {"", config::set{{"a", "b", 42}}}};
    constexpr auto skey_hex =
            "79f530dbf3d81aecc04072933c1b3e3edc0b7d91f2dcc2f7756f2611886cca5f"
            "4384261cdd338f5820ca9cbbe3fc72ac8944ee60d3b795b797fbbf5597b09f17"sv;
    std::array<unsigned char, 64> secretkey;
    oxenc::from_hex(skey_hex.begin(), skey_hex.end(), secretkey.begin());
    m.sign = [&secretkey](const unsigned char* data, size_t len) {
        std::array<unsigned char, 64> result;
        crypto_sign_ed25519_detached(result.data(), nullptr, data, len, secretkey.data());
        return result;
    };

    // clang-format off
    auto m_signing_value =
        "d"
          "1:#" "i10e"
          "1:&" "d"
            "3:bar" "d"
              "0:" "li42e1:a1:be"
              "4:asdf" "i123e"
              "3:xyz" "3:abc"
            "e"
            "3:foo" "i123e"
          "e"
          "1:<" "le"
          "1:=" "d"
            "3:bar" "d"
              "0:" "lli42e1:a1:belee"
              "4:asdf" "0:"
              "3:xyz" "0:"
            "e"
            "3:foo" "0:"
          "e"
          "1:~" "64:" + std::string(64, 0) +
        "e";
    // clang-format on

    auto m_expected = m_signing_value.substr(0, m_signing_value.size() - 65);
    auto expected_sig = oxenc::from_hex(
            "7f97bff4189ad6ae93443c200d06e43b0a118e6532aad5bfcca2dc60961bac4c"
            "e0e240f4fa1b5cd5fbfdcdb61e55f0642a90b45d36362b6395b3eea1f7382902");
    std::string sig(64, '\0');
    // Sign it ourselves, with the nulls in place, and check what we get:
    crypto_sign_ed25519_detached(
            reinterpret_cast<unsigned char*>(sig.data()),
            nullptr,
            reinterpret_cast<const unsigned char*>(m_signing_value.data()),
            m_signing_value.size(),
            secretkey.data());
    CHECK(oxenc::to_hex(sig) == oxenc::to_hex(expected_sig));
    m_expected += expected_sig;
    m_expected += 'e';
    CHECK(printable(m.serialize()) == printable(m_expected));
}

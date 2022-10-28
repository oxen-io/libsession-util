#include <oxenc/bt_serialize.h>

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

    m = m.increment();
    CHECK(m.diff().empty());
    m.data.erase("foo");

    diff = m.diff();
    CHECK(diff.size() == 1);
    CHECK(diff == bt_dict{{"foo", "-"sv}});

    m = m.increment();
    CHECK(m.diff().empty());

    m.data["foo"] = 123;
    d(m.data["bar"])["xyz"] = 42;
    d(m.data["bar"])["a"] = 42;
    s(d(m.data["bar"])[""]).insert("c");
    s(d(m.data["bar"])[""]).insert(99);
    s(d(m.data["bar"])[""]).erase("b");
    s(d(m.data["bar"])[""]).insert(42);  // already present

    diff = m.diff();
    CHECK(diff.size() == 2);
    CHECK(diff == bt_dict{{"foo", ""sv},
                          {"bar",
                           bt_dict{{"xyz", ""sv},
                                   {"a", ""sv},
                                   {"", bt_list{{bt_list{{99, "c"s}}, bt_list{{"b"s}}}}}}}});
}

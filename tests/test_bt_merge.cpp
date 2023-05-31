#include <rapidcheck.h>

#include <catch2/catch_test_macros.hpp>

#include "bt_cmp.hpp"
#include "catch2_bt_format.hpp"
#include "rapidcheck/catch.h"
#include "rc_gen_bt_value.hpp"
#include "session/bt_merge.hpp"

using oxenc::bt_dict;
using oxenc::bt_list;
using oxenc::bt_value;

TEST_CASE("bt_dict operator== properties", "[bt_dict][operator==]") {
    rc::check(
            "[bt_dict][operator==] order insensitive",
            [](const std::string& x_k,
               const std::string& y_k,
               const bt_value& x_v,
               const bt_value& y_v) {
                auto x = bt_dict{{x_k, x_v}};
                auto y = bt_dict{{y_k, y_v}};
                auto xy = bt_dict{{x_k, x_v}, {y_k, y_v}};
                auto yx = bt_dict{{y_k, y_v}, {x_k, x_v}};
                if (x_k == y_k) {
                    REQUIRE(xy == x);
                    REQUIRE(yx == y);
                } else {
                    REQUIRE(xy == yx);
                }
            });
}

TEST_CASE("bt_dict merging", "[bt_dict][merge]") {
    bt_dict x{{"a", 1}, {"b", 2}, {"c", 3}};
    bt_dict y{{"a", 42}, {"b", -123}, {"x", 12}, {"y", 17}, {"Z", 4}};

    CHECK(session::bt::merge(x, y) ==
          bt_dict{{"a", 1}, {"b", 2}, {"c", 3}, {"x", 12}, {"y", 17}, {"Z", 4}});

    CHECK(session::bt::merge(y, x) ==
          bt_dict{{"a", 42}, {"b", -123}, {"c", 3}, {"x", 12}, {"y", 17}, {"Z", 4}});

    CHECK(session::bt::merge(x, bt_dict{}) == x);
    CHECK(session::bt::merge(bt_dict{}, x) == x);
    CHECK(session::bt::merge(y, bt_dict{}) == y);
    CHECK(session::bt::merge(bt_dict{}, y) == y);
    CHECK(session::bt::merge(bt_dict{}, bt_dict{}) == bt_dict{});
}

namespace session::bt {
TEST_CASE("bt_dict merging properties", "[bt_dict][merge]") {
    rc::check("[bt_dict][merge] identity element", [](const bt_dict& x) {
        auto e = bt_dict{};
        REQUIRE(merge(e, e) == e);
        REQUIRE(merge(x, e) == x);
        REQUIRE(merge(e, x) == x);
    });

    rc::check(
            "[bt_dict][merge] singleton dict",
            [](const bt_dict& x, const std::string& y_k, const bt_value& y_v) {
                auto y = bt_dict{{y_k, y_v}};
                auto xy = merge(x, y);
                auto yx = merge(y, x);

                if (x.count(y_k) > 0) {
                    REQUIRE(xy.size() == x.size());
                    REQUIRE(yx.size() == x.size());

                    REQUIRE(xy.at(y_k) == x.at(y_k));
                    REQUIRE(yx.at(y_k) == y.at(y_k));
                } else {
                    REQUIRE(xy.size() == x.size() + 1);
                    REQUIRE(yx.size() == x.size() + 1);

                    REQUIRE(xy.at(y_k) == y.at(y_k));
                    REQUIRE(yx.at(y_k) == y.at(y_k));
                }
            });

    rc::check("[bt_dict][merge] self merge", [](const bt_dict& x) { REQUIRE(merge(x, x) == x); });

    rc::check(
            "[bt_dict][merge] associative",
            [](const bt_dict& x, const bt_dict& y, const bt_dict& z) {
                REQUIRE(merge(merge(x, y), z) == merge(x, merge(y, z)));
            });

    rc::check(
            "[bt_dict][merge] distributive",
            [](const bt_dict& x, const bt_dict& y, const bt_dict& z) {
                REQUIRE(merge(x, merge(y, z)) == merge(merge(x, y), merge(x, z)));
            });

    rc::check("[bt_dict][merge] left priority", [](const bt_dict& x, const bt_dict& y) {
        auto a = merge(x, y);
        auto b = merge(y, x);
        REQUIRE(merge(a, b) == a);
    });
}
}  // namespace session::bt

TEST_CASE("bt_list sorted merge", "[bt_list][merge]") {
    bt_list x{1, 2, 3, 5, 8, 13, 21};
    bt_list y{2, 4, 8, 16};

    auto compare = [](const auto& a, const auto& b) {
        return var::get<int64_t>(a) < var::get<int64_t>(b);
    };

    CHECK(session::bt::merge_sorted(x, y, compare) == bt_list{1, 2, 3, 4, 5, 8, 13, 16, 21});

    CHECK(session::bt::merge_sorted(x, y, compare, true) ==
          bt_list{1, 2, 2, 3, 4, 5, 8, 8, 13, 16, 21});

    CHECK(session::bt::merge_sorted(bt_list{1, 2}, bt_list{2}, compare) == bt_list{1, 2});
    CHECK(session::bt::merge_sorted(bt_list{1, 2}, bt_list{2}, compare, true) == bt_list{1, 2, 2});
    CHECK(session::bt::merge_sorted(bt_list{2}, bt_list{2}, compare) == bt_list{2});
    CHECK(session::bt::merge_sorted(bt_list{}, bt_list{2}, compare) == bt_list{2});
    CHECK(session::bt::merge_sorted(bt_list{2}, bt_list{}, compare) == bt_list{2});
    CHECK(session::bt::merge_sorted(bt_list{}, bt_list{}, compare) == bt_list{});
    CHECK(session::bt::merge_sorted(bt_list{}, bt_list{}, compare, true) == bt_list{});
}

bt_list unique_sorted(const bt_list& list) {
    std::set<bt_value> unique_values(list.begin(), list.end());
    bt_list sorted_list(unique_values.begin(), unique_values.end());
    sorted_list.sort(bt_cmp);
    return sorted_list;
}

bt_list gen_unique_sorted_bt_list() {
    return unique_sorted(*rc::gen::arbitrary<bt_list>());
}

namespace session::bt {
TEST_CASE("bt_list sorted merge properties", "[bt_list][merge]") {
    rc::check("[bt_list][merge] identity element", []() {
        auto e = bt_list{};
        auto x = gen_unique_sorted_bt_list();
        auto duplicates = *rc::gen::arbitrary<bool>();
        REQUIRE(merge_sorted(e, e, bt_cmp, duplicates) == e);
        REQUIRE(merge_sorted(x, e, bt_cmp, duplicates) == x);
        REQUIRE(merge_sorted(e, x, bt_cmp, duplicates) == x);
    });

    rc::check("[bt_list][merge] singleton list", []() {
        auto x = gen_unique_sorted_bt_list();
        auto v = bt_value{*rc::gen::arbitrary<int64_t>()};
        auto y = bt_list{v};
        auto xy = merge_sorted(x, y, bt_cmp, false);
        if (std::find(x.begin(), x.end(), v) != x.end()) {
            REQUIRE(xy == x);
        } else {
            REQUIRE(xy.size() == x.size() + 1);
            REQUIRE(std::find(xy.begin(), xy.end(), v) != xy.end());
        }
    });

    rc::check("[bt_list][merge] duplicates", []() {
        auto x = gen_unique_sorted_bt_list();
        auto y = gen_unique_sorted_bt_list();
        auto xy = merge_sorted(x, y, bt_cmp, true);
        REQUIRE(xy.size() == x.size() + y.size());
    });

    rc::check("[bt_list][merge] self merge", []() {
        auto x = gen_unique_sorted_bt_list();
        REQUIRE(merge_sorted(x, x, bt_cmp, false) == x);
    });

    rc::check("[bt_list][merge] communicative", []() {
        auto x = gen_unique_sorted_bt_list();
        auto y = gen_unique_sorted_bt_list();
        auto duplicates = *rc::gen::arbitrary<bool>();
        auto xy = merge_sorted(x, y, bt_cmp, duplicates);
        auto yx = merge_sorted(y, x, bt_cmp, duplicates);
        REQUIRE(xy == yx);
    });

    rc::check("[bt_list][merge] associative", []() {
        auto x = gen_unique_sorted_bt_list();
        auto y = gen_unique_sorted_bt_list();
        auto z = gen_unique_sorted_bt_list();
        auto duplicates = *rc::gen::arbitrary<bool>();

        auto xy = merge_sorted(x, y, bt_cmp, duplicates);
        auto xy_z = merge_sorted(xy, z, bt_cmp, duplicates);

        auto yz = merge_sorted(y, z, bt_cmp, duplicates);
        auto x_yz = merge_sorted(x, yz, bt_cmp, duplicates);

        REQUIRE(xy_z == x_yz);
    });
}

}  // namespace session::bt

#include <rapidcheck.h>

#include <catch2/catch_test_macros.hpp>

#include "rc_gen_bt_value.hpp"
#include "catch2_bt_format.hpp"
#include "rapidcheck/catch.h"
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

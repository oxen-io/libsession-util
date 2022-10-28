#include "session/config.hpp"

#include <iostream>

#include <oxenc/bt_serialize.h>
#include <optional>
#include <variant>
#include <oxenc/variant.h>

#include "session/bt_merge.hpp"

using namespace std::literals;

namespace session::config {

namespace {

// prune functions: return true if, after pruning any subvalues, the value should be removed.
bool prune_(dict_value& v);
bool prune_(dict& d) {
    for (auto it = d.begin(); it != d.end();) {
        if (prune_(it->second))
            it = d.erase(it);
        else
            ++it;
    }
    return d.empty();
}
bool prune_(scalar&) {
    return false;
}
bool prune_(set& s) {
    return s.empty();
}
bool prune_(dict_value& v) {
    return std::visit([](auto& x) { return prune_(x); }, v);
}

// diff helper functions
std::optional<oxenc::bt_list> diff_(const set& old, const set& new_) {
    set added, removed;

    auto oldit = old.begin(), newit = new_.begin();

    while (oldit != old.end() || newit != new_.end()) {
        if (oldit == old.end() || (
                    newit != new_.end() && *newit < *oldit)) {
            added.insert(added.end(), *newit);
            ++newit;
        } else if (newit == new_.end() || (
                    oldit != old.end() && *oldit < *newit)) {
            removed.insert(removed.end(), *oldit);
            ++oldit;
        } else {
            // both are set, and equal
            ++newit;
            ++oldit;
        }
    }

    if (added.empty() && removed.empty())
        return std::nullopt;

    oxenc::bt_list additions, removals;
    for (auto& a : added)
        std::visit([&additions] (auto& x) {
            additions.emplace_back(std::move(x));
        }, a);
    for (auto& r : removed)
        std::visit([&removals] (auto& x) {
            removals.emplace_back(std::move(x));
        }, r);

    return oxenc::bt_list{{std::move(additions)}, {std::move(removals)}};
}

std::optional<oxenc::bt_dict> diff_(const dict& old, const dict& new_) {
    auto result = std::make_optional<oxenc::bt_dict>();
    auto& df = *result;

    auto oldit = old.begin(), newit = new_.begin();
    while (oldit != old.end() || newit != new_.end()) {
        bool is_new = false;
        if (oldit == old.end() ||
                (newit != new_.end() && newit->first < oldit->first)) {
            // newit is a new item; fall through to handle below

        } else if (newit == new_.end() ||
                (oldit != old.end() && oldit->first < newit->first)) {

            // oldit got removed
            const auto& key = oldit->first;
            if (auto* d = std::get_if<dict>(&oldit->second))
                df[key] = *diff_(*d, {});
            else if (auto* s = std::get_if<set>(&oldit->second))
                df[key] = *diff_(*s, {});
            else
                df[key] = "-"sv;

            ++oldit;
            continue;

        } else {
            // same key in old and new
            auto& o = oldit->second;
            auto& n = newit->second;
            if (o.index() != n.index()) {
                // The fundamental type (scalar, dict, set) changed, so we'll treat this as a new
                // value (which implicitly deletes a value of a wrong type when merging).
                is_new = true;
                ++oldit;
                // fall through to handler below

            } else {
                const auto& key = newit->first;
                if (auto* ov = std::get_if<scalar>(&o)) {
                    if (*ov != var::get<scalar>(n))
                        df[key] = ""sv;
                } else if (auto* dv = std::get_if<dict>(&o)) {
                    if (auto subdiff = diff_(*dv, var::get<dict>(n)))
                        df[key] = std::move(*subdiff);
                } else if (auto subdiff = diff_(var::get<set>(o), var::get<set>(n))) {
                    df[key] = std::move(*subdiff);
                }
                ++oldit;
                ++newit;
                continue;
            }
        }

        // If we're here then either it's a new key, or we're treating it as a new key because the
        // fundamental type changed.
        const auto& key = newit->first;
        if (auto* d = std::get_if<dict>(&newit->second))
            df[key] = *diff_({}, *d);
        else if (auto* s = std::get_if<set>(&newit->second))
            df[key] = *diff_({}, *s);
        else
            df[key] = ""sv;
        ++newit;
    }

    if (df.empty())
        result.reset();

    return result;
}

}

void ConfigMessage::prune() {
    prune_(data);
}


ConfigMessage ConfigMessage::increment() const {
    ConfigMessage copy{*this};
    copy.prune();
    copy.orig_data_ = copy.data;
    return copy;
}

oxenc::bt_dict ConfigMessage::diff() {
    prune();
    return diff_(orig_data_, data).value_or(oxenc::bt_dict{});
}


}  // namespace session::config

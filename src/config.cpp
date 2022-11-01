#include "session/config.hpp"

#include <oxenc/bt_producer.h>
#include <oxenc/bt_value_producer.h>
#include <oxenc/variant.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <iostream>
#include <optional>
#include <type_traits>
#include <variant>

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
    bool prune_(scalar&) { return false; }
    bool prune_(set& s) { return s.empty(); }
    bool prune_(dict_value& v) {
        return std::visit([](auto& x) { return prune_(x); }, v);
    }

    // diff helper functions
    std::optional<oxenc::bt_list> diff_(const set& old, const set& new_) {
        set added, removed;

        auto oldit = old.begin(), newit = new_.begin();

        while (oldit != old.end() || newit != new_.end()) {
            if (oldit == old.end() || (newit != new_.end() && *newit < *oldit)) {
                added.insert(added.end(), *newit);
                ++newit;
            } else if (newit == new_.end() || (oldit != old.end() && *oldit < *newit)) {
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
            std::visit([&additions](auto& x) { additions.emplace_back(std::move(x)); }, a);
        for (auto& r : removed)
            std::visit([&removals](auto& x) { removals.emplace_back(std::move(x)); }, r);

        return oxenc::bt_list{{std::move(additions)}, {std::move(removals)}};
    }

    std::optional<oxenc::bt_dict> diff_(const dict& old, const dict& new_) {
        auto result = std::make_optional<oxenc::bt_dict>();
        auto& df = *result;

        auto oldit = old.begin(), newit = new_.begin();
        while (oldit != old.end() || newit != new_.end()) {
            bool is_new = false;
            if (oldit == old.end() || (newit != new_.end() && newit->first < oldit->first)) {
                // newit is a new item; fall through to handle below

            } else if (newit == new_.end() || (oldit != old.end() && oldit->first < newit->first)) {

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
                    // The fundamental type (scalar, dict, set) changed, so we'll treat this as a
                    // new value (which implicitly deletes a value of a wrong type when merging).
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

            // If we're here then either it's a new key, or we're treating it as a new key because
            // the fundamental type changed.
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

    void serialize_data(oxenc::bt_list_producer&& out, const set& s);
    void serialize_data(oxenc::bt_dict_producer&& out, const dict& d) {
        for (auto& pair : d) {
            std::visit(
                    [&](const auto& v) {
                        auto& k = pair.first;
                        using T = std::remove_cv_t<std::remove_reference_t<decltype(v)>>;
                        if constexpr (std::is_same_v<T, dict>)
                            serialize_data(out.append_dict(k), v);
                        else if constexpr (std::is_same_v<T, set>)
                            serialize_data(out.append_list(k), v);
                        else
                            std::visit(
                                    [&](const auto& scalar) { out.append(pair.first, scalar); }, v);
                    },
                    pair.second);
        }
    }
    void serialize_data(oxenc::bt_list_producer&& out, const set& s) {
        for (auto& val : s)
            std::visit([&](const auto& scalar) { out.append(scalar); }, val);
    }

    constexpr std::string_view null_sig =
            "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"sv;

}  // namespace

void ConfigMessage::prune() {
    prune_(data);
}

ConfigMessage ConfigMessage::increment() const {
    ConfigMessage copy{*this};
    auto lag_seqno = seqno;
    auto lag_hash = copy.hash();
    auto lag_diff = diff_(copy.orig_data_, copy.data).value_or(oxenc::bt_dict{});
    copy.seqno++;
    copy.orig_data_ = copy.data;
    copy.lagged_diffs_.emplace_hint(
            copy.lagged_diffs_.end(), lag_seqno, lag_hash, std::move(lag_diff));
    return copy;
}

oxenc::bt_dict ConfigMessage::diff() {
    prune();
    return diff_(orig_data_, data).value_or(oxenc::bt_dict{});
}

std::string ConfigMessage::serialize() {
    auto curr_diff = diff();  // also prune()s
    std::string result;
    result.resize(MAX_MESSAGE_SIZE);
    oxenc::bt_dict_producer outer{result.data(), result.size()};

    try {
        outer.append("#", seqno);
        serialize_data(outer.append_dict("&"), data);
        {
            auto lags = outer.append_list("<");
            for (auto& [lag_seqno, lag_hash, lag_data] : lagged_diffs_) {
                if (lag_seqno <= seqno - lag || lag_seqno >= seqno)
                    continue;
                auto lag = lags.append_list();
                lag.append(lag_seqno);
                lag.append(std::string_view{
                        reinterpret_cast<const char*>(lag_hash.data()), lag_hash.size()});
                lag.append_bt(lag_data);
            }
        }
        outer.append_bt("=", curr_diff);

        if (sign) {
            outer.append("~", null_sig);
            // We're going to get a bit dirty here with overwriting the signature bytes, so make
            // sure it ended up exactly where we expect it:
            auto sig_begin = result.data() + outer.view().size() - 65;
            assert(std::string_view(sig_begin - 6, 6) == "1:~64:");
            assert(std::string_view(sig_begin, 64) == null_sig);
            assert(std::string_view(sig_begin + 64, 1) == "e");

            auto sig = sign(
                    reinterpret_cast<unsigned char*>(result.data()), outer.end() - result.data());
            static_assert(sig.size() == null_sig.size());
            std::memcpy(sig_begin, sig.data(), 64);
        }
    } catch (const std::length_error&) {
        throw std::length_error{"Config data is too large"};
    }
    result.resize(outer.view().size());
    return result;
}

std::array<unsigned char, 32> ConfigMessage::hash(std::string_view serialized) {
    std::string tmp;
    if (serialized.empty()) {
        tmp = serialize();
        serialized = tmp;
    }

    std::array<unsigned char, 32> result;
    crypto_generichash_blake2b(
            result.data(),
            result.size(),
            reinterpret_cast<const unsigned char*>(serialized.data()),
            serialized.size(),
            nullptr,
            0);

    return result;
}

}  // namespace session::config

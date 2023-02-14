#include "session/config/community.hpp"

#include <oxenc/hex.h>

#include <charconv>
#include <optional>
#include <session/types.hpp>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include "internal.hpp"
#include "oxenc/base32z.h"
#include "oxenc/base64.h"
#include "session/util.hpp"

namespace session::config {

community::community(std::string_view base_url_, std::string_view room_) {
    set_base_url(std::move(base_url_));
    set_room(std::move(room_));
}

community::community(std::string_view base_url, std::string_view room, ustring_view pubkey_) :
        community{base_url, room} {
    set_pubkey(pubkey_);
}

community::community(
        std::string_view base_url, std::string_view room, std::string_view pubkey_encoded) :
        community{base_url, room} {
    set_pubkey(pubkey_encoded);
}

void community::set_full_url(std::string_view full_url) {
    auto [b_url, r_token, s_pubkey] = parse_full_url(full_url);
    base_url_ = std::move(b_url);
    set_room(std::move(r_token));
    pubkey_ = std::move(s_pubkey);
}

void community::set_base_url(std::string_view new_url) {
    base_url_ = canonical_url(new_url);
}

void community::set_pubkey(ustring_view pubkey) {
    if (pubkey.size() != 32)
        throw std::invalid_argument{"Invalid pubkey: expected a 32-byte pubkey"};
    pubkey_ = pubkey;
}
void community::set_pubkey(std::string_view pubkey) {
    pubkey_ = decode_pubkey(pubkey);
}

std::string community::pubkey_hex() const {
    const auto& pk = pubkey();
    return oxenc::to_hex(pk.begin(), pk.end());
}

std::string community::pubkey_b32z() const {
    const auto& pk = pubkey();
    return oxenc::to_base32z(pk.begin(), pk.end());
}

std::string community::pubkey_b64() const {
    const auto& pk = pubkey();
    return oxenc::to_base64(pk.begin(), pk.end());
}

void community::set_room(std::string_view room) {
    room_ = canonical_room(room);  // Also validates and throws on error
    localized_room_ = room;
}

// returns protocol, host, port.  Port can be empty; throws on unparseable values.  protocol and
// host get normalized to lower-case.  Port will be 0 if not present in the URL, or if set to
// the default for the protocol. The URL must not include a path (though a single optional `/`
// after the domain is accepted and ignored).
std::tuple<std::string, std::string, uint16_t> parse_url(std::string_view url) {
    std::tuple<std::string, std::string, uint16_t> result{};
    auto& [proto, host, port] = result;
    if (auto pos = url.find("://"); pos != std::string::npos) {
        auto proto_name = url.substr(0, pos);
        url.remove_prefix(proto_name.size() + 3);
        if (string_iequal(proto_name, "http"))
            proto = "http://";
        else if (string_iequal(proto_name, "https"))
            proto = "https://";
    }
    if (proto.empty())
        throw std::invalid_argument{"Invalid community URL: invalid/missing protocol://"};

    bool next_allow_dot = false;
    bool has_dot = false;
    while (!url.empty()) {
        auto c = url.front();
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '-') {
            host += c;
            next_allow_dot = true;
        } else if (c >= 'A' && c <= 'Z') {
            host += c + ('a' - 'A');
            next_allow_dot = true;
        } else if (next_allow_dot && c == '.') {
            host += '.';
            has_dot = true;
            next_allow_dot = false;
        } else {
            break;
        }
        url.remove_prefix(1);
    }
    if (host.size() < 4 || !has_dot || host.back() == '.')
        throw std::invalid_argument{"Invalid community URL: invalid hostname"};

    if (!url.empty() && url.front() == ':') {
        url.remove_prefix(1);
        if (auto [p, ec] = std::from_chars(url.data(), url.data() + url.size(), port);
            ec == std::errc{})
            url.remove_prefix(p - url.data());
        else
            throw std::invalid_argument{"Invalid community URL: invalid port"};
        if ((port == 80 && proto == "http://") || (port == 443 && proto == "https://"))
            port = 0;
    }

    if (!url.empty() && url.front() == '/')
        url.remove_prefix(1);

    // We don't (currently) allow a /path in a community URL
    if (!url.empty())
        throw std::invalid_argument{"Invalid community URL: found unexpected trailing value"};

    return result;
}

void community::canonicalize_url(std::string& url) {
    if (auto new_url = canonical_url(url); new_url != url)
        url = std::move(new_url);
}

void community::canonicalize_room(std::string& room) {
    for (auto& c : room)
        if (c >= 'A' && c <= 'Z')
            c += ('a' - 'A');
    if (room.size() > ROOM_MAX_LENGTH)
        throw std::invalid_argument{"Invalid community room: room token is too long"};
    if (room.empty())
        throw std::invalid_argument{"Invalid community room: room token cannot be empty"};
    if (room.find_first_not_of("-0123456789_abcdefghijklmnopqrstuvwxyz") != std::string_view::npos)
        throw std::invalid_argument{
                "Invalid community URL: room token contains invalid characters"};
}

std::string community::canonical_url(std::string_view url) {
    const auto& [proto, host, port] = parse_url(url);
    std::string result;
    result += proto;
    result += host;
    if (port != 0) {
        result += ':';
        result += std::to_string(port);
    }
    if (result.size() > URL_MAX_LENGTH)
        throw std::invalid_argument{"Invalid community URL: base URL is too long"};
    return result;
}

std::string community::canonical_room(std::string_view room) {
    std::string r{room};
    canonicalize_room(r);
    return r;
}

static constexpr std::string_view qs_pubkey{"?public_key="};

std::tuple<std::string, std::string, ustring> community::parse_full_url(std::string_view full_url) {
    std::tuple<std::string, std::string, ustring> result;
    auto& [base_url, room_token, pubkey] = result;

    // Consume the URL from back to front; first the public key:
    if (auto pos = full_url.rfind(qs_pubkey); pos != std::string_view::npos) {
        auto pk = full_url.substr(pos + qs_pubkey.size());
        pubkey = decode_pubkey(pk);
        full_url = full_url.substr(0, pos);
    } else {
        throw std::invalid_argument{"Invalid community URL: no valid server pubkey"};
    }

    // Now look for /r/TOKEN or /TOKEN:
    if (auto pos = full_url.rfind("/r/"); pos != std::string_view::npos) {
        room_token = full_url.substr(pos + 3);
        full_url = full_url.substr(0, pos);
    } else if (pos = full_url.rfind("/"); pos != std::string_view::npos) {
        room_token = full_url.substr(pos + 1);
        full_url = full_url.substr(0, pos);
    }

    base_url = canonical_url(full_url);

    return result;
}

}  // namespace session::config

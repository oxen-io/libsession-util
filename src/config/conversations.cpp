#include "session/config/conversations.hpp"

#include <oxenc/hex.h>
#include <oxenc/variant.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <iostream>
#include <iterator>
#include <stdexcept>
#include <variant>

#include "internal.hpp"
#include "session/config/conversations.h"
#include "session/config/error.h"
#include "session/export.h"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using session::ustring_view;

namespace {

void check_session_id(std::string_view session_id) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{
                "Invalid pubkey: expected 66 hex digits, got " + std::to_string(session_id.size()) +
                " and/or not hex"};
}

std::string session_id_to_bytes(std::string_view session_id) {
    check_session_id(session_id);
    return oxenc::from_hex(session_id);
}

void check_open_group_pubkey(std::string_view pk) {
    if (pk.size() != 64 || !oxenc::is_hex(pk))
        throw std::invalid_argument{"Invalid open group pubkey: expected 64 hex digits"};
}

std::string open_group_pubkey_to_bytes(std::string_view o_g_pk_hex) {
    check_open_group_pubkey(o_g_pk_hex);
    return oxenc::from_hex(o_g_pk_hex);
}

void make_lc(std::string& s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z')
            c += ('a' - 'A');
}

// Digs into a dict to get out an int64_t; nullopt if not there (or not int)
static std::optional<int64_t> maybe_int(const session::config::dict& d, const char* key) {
    if (auto it = d.find(key); it != d.end())
        if (auto* sc = std::get_if<session::config::scalar>(&it->second))
            if (auto* i = std::get_if<int64_t>(sc))
                return *i;
    return std::nullopt;
}

}  // namespace

namespace session::config {

namespace convo {

    one_to_one::one_to_one(std::string&& sid) : session_id{std::move(sid)} {
        check_session_id(session_id);
    }
    one_to_one::one_to_one(std::string_view sid) : session_id{sid} {
        check_session_id(session_id);
    }
    one_to_one::one_to_one(const struct convo_one_to_one& c) :
            session_id{c.session_id, 66},
            last_read{c.last_read},
            expiration{static_cast<expiration_mode>(c.exp_mode)},
            expiration_timer{c.exp_minutes} {}

    void one_to_one::into(convo_one_to_one& c) const {
        std::memcpy(c.session_id, session_id.data(), 67);
        c.last_read = last_read;
        c.exp_mode = static_cast<CONVO_EXPIRATION_MODE>(expiration);
        c.exp_minutes = expiration_timer.count();
    }

    open_group::open_group(
            std::string_view base_url_, std::string_view room_, ustring_view pubkey_) {
        set_server(base_url_, room_, pubkey_);
    }

    open_group::open_group(
            std::string_view base_url_, std::string_view room_, std::string_view pubkey_hex_) {
        set_server(base_url_, room_, pubkey_hex_);
    }

    open_group::open_group(const struct convo_open_group& c) : last_read{c.last_read} {
        set_server(c.base_url, c.room, ustring_view{c.pubkey, 32});
    }

    void open_group::set_server(
            std::string_view base_url_, std::string_view room_, ustring_view pubkey_) {
        key = make_key(base_url_, room_, pubkey_);
        url_size = base_url_.size();
    }

    void open_group::set_server(
            std::string_view base_url_, std::string_view room_, std::string_view pubkey_hex_) {
        key = make_key(base_url_, room_, pubkey_hex_);
        url_size = base_url_.size();
    }

    void open_group::load_encoded_key(std::string k) {
        size_t new_url_size = k.find('\0');
        if (new_url_size == std::string::npos)
            throw std::invalid_argument{
                    "Invalid encoded open group url: did not find URL/room separator"};
        size_t pk_sep_pos = k.find('\0', new_url_size + 1);
        if (pk_sep_pos == std::string::npos)
            throw std::invalid_argument{
                    "Invalid encoded open group url: did not find room/pubkey separator"};
        if (pk_sep_pos + 33 != k.size())
            throw std::invalid_argument{"Invalid encoded open group url: did not find pubkey"};

        key = std::move(k);
        url_size = new_url_size;
    }

    std::string_view open_group::base_url() const {
        return {key.data(), url_size};
    }
    std::string_view open_group::room() const {
        if (key.empty())
            return {};
        std::string_view r{key};
        r.remove_prefix(url_size + 1 /*null separator*/);
        r.remove_suffix(1 /*null separator*/ + 32 /*pubkey*/);
        return r;
    }
    ustring_view open_group::pubkey() const {
        const auto* data = reinterpret_cast<const unsigned char*>(key.data());
        if (key.empty())
            return {data, 0};
        return {data + (key.size() - 32), 32};
    }
    std::string open_group::pubkey_hex() const {
        auto pk = pubkey();
        return oxenc::to_hex(pk.begin(), pk.end());
    }

    void open_group::into(convo_open_group& c) const {
        static_assert(sizeof(c.base_url) == MAX_URL + 1);
        static_assert(sizeof(c.room) == MAX_ROOM + 1);
        copy_c_str(c.base_url, base_url());
        copy_c_str(c.room, room());
        std::memcpy(c.pubkey, pubkey().data(), 32);
        c.last_read = last_read;
    }

    legacy_closed_group::legacy_closed_group(std::string&& cgid) : id{std::move(cgid)} {
        check_session_id(id);
    }
    legacy_closed_group::legacy_closed_group(std::string_view cgid) : id{cgid} {
        check_session_id(id);
    }
    legacy_closed_group::legacy_closed_group(const struct convo_legacy_closed_group& c) :
            id{c.group_id, 66}, last_read{c.last_read} {}

    void legacy_closed_group::into(convo_legacy_closed_group& c) const {
        std::memcpy(c.group_id, id.data(), 67);
        c.last_read = last_read;
    }

    void one_to_one::load(const dict& info_dict) {
        last_read = maybe_int(info_dict, "r").value_or(0);
        auto exp = maybe_int(info_dict, "e").value_or(0);
        expiration =
                exp == static_cast<int>(expiration_mode::after_send)   ? expiration_mode::after_send
                : exp == static_cast<int>(expiration_mode::after_read) ? expiration_mode::after_read
                                                                       : expiration_mode::none;
        if (expiration == expiration_mode::none)
            expiration_timer = 0min;
        else if (auto exp_mins = maybe_int(info_dict, "E").value_or(0); exp_mins > 0)
            expiration_timer = exp_mins * 1min;
        else {
            expiration = expiration_mode::none;
            expiration_timer = 0min;
        }
    }

    void open_group::load(const dict& info_dict) {
        last_read = maybe_int(info_dict, "r").value_or(0);
    }

    void legacy_closed_group::load(const dict& info_dict) {
        last_read = maybe_int(info_dict, "r").value_or(0);
    }

    std::string open_group::make_key(
            std::string_view base_url, std::string_view room, ustring_view pubkey) {
        if (pubkey.size() != 32)
            throw std::invalid_argument{"Invalid open group pubkey: expected 32 bytes"};
        if (base_url.size() > MAX_URL)
            throw std::invalid_argument{"Invalid open group URL: base URL is too long"};
        if (room.size() > MAX_ROOM)
            throw std::invalid_argument{"Invalid open group room: room token is too long"};
        std::string key;
        key.reserve(base_url.size() + room.size() + 32 /*pubkey*/ + 2 /* null separators */);
        for (auto c : base_url)
            key += (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
        key += '\0';
        for (auto c : room)
            key += (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
        key += '\0';
        key.resize(key.size() + 32);
        std::memcpy(key.data() + (key.size() - 32), pubkey.data(), 32);
        return key;
    }

    std::string open_group::make_key(
            std::string_view base_url, std::string_view room, std::string_view pubkey_hex) {
        check_open_group_pubkey(pubkey_hex);
        ustring pubkey;
        pubkey.reserve(32);
        oxenc::from_hex(pubkey_hex.begin(), pubkey_hex.end(), std::back_inserter(pubkey));
        return make_key(base_url, room, pubkey);
    }

}  // namespace convo

Conversations::Conversations(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped) :
        ConfigBase{dumped} {
    load_key(ed25519_secretkey);
}

std::optional<convo::one_to_one> Conversations::get_1to1(std::string_view pubkey_hex) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["1"][pubkey].dict();
    if (!info_dict)
        return std::nullopt;

    auto result = std::make_optional<convo::one_to_one>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

convo::one_to_one Conversations::get_or_construct_1to1(std::string_view pubkey_hex) const {
    if (auto maybe = get_1to1(pubkey_hex))
        return *std::move(maybe);

    return convo::one_to_one{std::string{pubkey_hex}};
}

std::optional<convo::open_group> Conversations::get_open(
        std::string_view base_url, std::string_view room, ustring_view pubkey) const {
    auto result = std::make_optional<convo::open_group>(base_url, room, pubkey);

    if (auto* info_dict = data["o"][result->key].dict())
        result->load(*info_dict);
    else
        result.reset();

    return result;
}

std::optional<convo::open_group> Conversations::get_open(
        std::string_view base_url, std::string_view room, std::string_view pubkey_hex) const {
    auto result = std::make_optional<convo::open_group>(base_url, room, pubkey_hex);

    if (auto* info_dict = data["o"][result->key].dict())
        result->load(*info_dict);
    else
        result.reset();

    return result;
}

convo::open_group Conversations::get_or_construct_open(
        std::string_view base_url, std::string_view room, ustring_view pubkey) const {
    convo::open_group result{base_url, room, pubkey};

    if (auto* info_dict = data["o"][result.key].dict())
        result.load(*info_dict);

    return result;
}

convo::open_group Conversations::get_or_construct_open(
        std::string_view base_url, std::string_view room, std::string_view pubkey_hex) const {
    convo::open_group result{base_url, room, pubkey_hex};

    if (auto* info_dict = data["o"][result.key].dict())
        result.load(*info_dict);

    return result;
}

std::optional<convo::legacy_closed_group> Conversations::get_legacy_closed(
        std::string_view pubkey_hex) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["C"][pubkey].dict();
    if (!info_dict)
        return std::nullopt;

    auto result = std::make_optional<convo::legacy_closed_group>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

convo::legacy_closed_group Conversations::get_or_construct_legacy_closed(
        std::string_view pubkey_hex) const {
    if (auto maybe = get_legacy_closed(pubkey_hex))
        return *std::move(maybe);

    return convo::legacy_closed_group{std::string{pubkey_hex}};
}

void Conversations::set(const convo::one_to_one& c) {
    std::string pk = session_id_to_bytes(c.session_id);
    auto info = data["1"][pk];

    info["r"] = c.last_read;
    if (c.expiration != convo::expiration_mode::none && c.expiration_timer != 0min) {
        info["e"] = static_cast<int8_t>(c.expiration);
        info["E"] = c.expiration_timer.count();
    } else {
        info["e"].erase();
        info["E"].erase();
    }
}

void Conversations::set(const convo::open_group& c) {
    auto info = data["o"][c.key];
    info["r"] = c.last_read;
}

void Conversations::set(const convo::legacy_closed_group& c) {
    std::string pk = session_id_to_bytes(c.id);
    auto info = data["C"][pk];
    info["r"] = c.last_read;
}

template <typename Data>
static bool erase_impl(Data& data, std::string top_key, std::string sub_key) {
    auto convo = data[top_key][sub_key];
    bool ret = convo.exists();
    convo.erase();
    return ret;
}

bool Conversations::erase(const convo::one_to_one& c) {
    return erase_impl(data, "1", session_id_to_bytes(c.session_id));
}
bool Conversations::erase(const convo::open_group& c) {
    return erase_impl(data, "o", c.key);
}
bool Conversations::erase(const convo::legacy_closed_group& c) {
    return erase_impl(data, "C", session_id_to_bytes(c.id));
}

bool Conversations::erase(const convo::any& c) {
    return var::visit([this](const auto& c) { return erase(c); }, c);
}
bool Conversations::erase_1to1(std::string_view session_id) {
    return erase(convo::one_to_one{session_id});
}
bool Conversations::erase_open(
        std::string_view base_url, std::string_view room, std::string_view pubkey_hex) {
    return erase(convo::open_group{base_url, room, pubkey_hex});
}
bool Conversations::erase_open(
        std::string_view base_url, std::string_view room, ustring_view pubkey) {
    return erase(convo::open_group{base_url, room, pubkey});
}
bool Conversations::erase_legacy_closed(std::string_view id) {
    return erase(convo::legacy_closed_group{id});
}

Conversations::iterator Conversations::erase(iterator it) {
    auto remove_it = it++;
    erase(*remove_it);
    return it;
}

size_t Conversations::size_1to1() const {
    if (auto* d = data["1"].dict())
        return d->size();
    return 0;
}

size_t Conversations::size_open() const {
    if (auto* d = data["o"].dict())
        return d->size();
    return 0;
}

size_t Conversations::size_legacy_closed() const {
    if (auto* d = data["C"].dict())
        return d->size();
    return 0;
}

size_t Conversations::size() const {
    return size_1to1() + size_open() + size_legacy_closed();
}

Conversations::iterator::iterator(const DictFieldRoot& data, bool oneto1, bool open, bool closed) {
    if (oneto1)
        if (auto* d = data["1"].dict()) {
            _it_11 = d->begin();
            _end_11 = d->end();
        }
    if (open)
        if (auto* d = data["o"].dict()) {
            _it_open = d->begin();
            _end_open = d->end();
        }
    if (closed)
        if (auto* d = data["C"].dict()) {
            _it_lclosed = d->begin();
            _end_lclosed = d->end();
        }
    _load_val();
}

/// Load _val from the current iterator position; if it is invalid, skip to the next key until we
/// find one that is valid (or hit the end).  We also span across three different iterators: first
/// we exhaust _it_11, then _it_open, then _it_lclosed.
///
/// We *always* call this after incrementing the iterator (and after iterator initialization), and
/// this is responsible for making sure that _it_11, _it_open, etc. are only set to non-nullopt if
/// the respective sub-iterator is *not* at the end (and resetting them when we hit the end).  Thus,
/// after calling this, our "end" condition will be simply that all of the three iterators are
/// nullopt.
void Conversations::iterator::_load_val() {
    while (_it_11) {
        if (*_it_11 == *_end_11) {
            _it_11.reset();
            _end_11.reset();
            break;
        }

        auto& [k, v] = **_it_11;

        if (k.size() == 33 && k[0] == 0x05) {
            if (auto* info_dict = std::get_if<dict>(&v)) {
                _val = std::make_shared<convo::any>(convo::one_to_one{oxenc::to_hex(k)});
                std::get<convo::one_to_one>(*_val).load(*info_dict);
                return;
            }
        }
        ++*_it_11;
    }

    while (_it_open) {
        if (*_it_open == *_end_open) {
            _it_open.reset();
            _end_open.reset();
            break;
        }

        auto& [k, v] = **_it_open;

        auto* info_dict = std::get_if<dict>(&v);
        if (!info_dict) {
            ++*_it_open;
            continue;
        }

        _val = std::make_shared<convo::any>(convo::open_group{});
        auto& og = std::get<convo::open_group>(*_val);
        try {
            og.load_encoded_key(k);
        } catch (const std::exception& e) {
            ++*_it_open;
            continue;
        }
        og.load(*info_dict);
        return;
    }

    while (_it_lclosed) {
        if (*_it_lclosed == *_end_lclosed) {
            _it_lclosed.reset();
            _end_lclosed.reset();
            break;
        }

        auto& [k, v] = **_it_lclosed;

        if (k.size() == 33 && k[0] == 0x05) {
            if (auto* info_dict = std::get_if<dict>(&v)) {
                _val = std::make_shared<convo::any>(convo::legacy_closed_group{oxenc::to_hex(k)});
                std::get<convo::legacy_closed_group>(*_val).load(*info_dict);
                return;
            }
        }
        ++*_it_lclosed;
    }
}

bool Conversations::iterator::operator==(const iterator& other) const {
    return _it_11 == other._it_11 && _it_open == other._it_open && _it_lclosed == other._it_lclosed;
}

bool Conversations::iterator::done() const {
    return !(_it_11 || _it_open || _it_lclosed);
}

Conversations::iterator& Conversations::iterator::operator++() {
    if (_it_11)
        ++*_it_11;
    else if (_it_open)
        ++*_it_open;
    else {
        assert(_it_lclosed);
        ++*_it_lclosed;
    }
    _load_val();
    return *this;
}

}  // namespace session::config

using namespace session::config;

LIBSESSION_C_API
int conversations_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<Conversations>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API bool convos_get_1to1(
        const config_object* conf, convo_one_to_one* convo, const char* session_id) {
    try {
        if (auto c = unbox<Conversations>(conf)->get_1to1(session_id)) {
            c->into(*convo);
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API bool convos_get_or_construct_1to1(
        const config_object* conf, convo_one_to_one* convo, const char* session_id) {
    try {
        unbox<Conversations>(conf)->get_or_construct_1to1(session_id).into(*convo);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool convos_get_open_group(
        const config_object* conf,
        convo_open_group* og,
        const char* base_url,
        const char* room,
        unsigned const char* pubkey) {
    try {
        if (auto c = unbox<Conversations>(conf)->get_open(
                    base_url, room, ustring_view{pubkey, 32})) {
            c->into(*og);
            return true;
        }
    } catch (...) {
    }
    return false;
}
LIBSESSION_C_API bool convos_get_or_construct_open_group(
        const config_object* conf,
        convo_open_group* convo,
        const char* base_url,
        const char* room,
        unsigned const char* pubkey) {
    try {
        unbox<Conversations>(conf)
                ->get_or_construct_open(base_url, room, ustring_view{pubkey, 32})
                .into(*convo);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool convos_get_legacy_closed(
        const config_object* conf, convo_legacy_closed_group* convo, const char* id) {
    try {
        if (auto c = unbox<Conversations>(conf)->get_legacy_closed(id)) {
            c->into(*convo);
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API bool convos_get_or_construct_legacy_closed(
        const config_object* conf, convo_legacy_closed_group* convo, const char* id) {
    try {
        unbox<Conversations>(conf)->get_or_construct_legacy_closed(id).into(*convo);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API void convos_set_1to1(config_object* conf, const convo_one_to_one* convo) {
    unbox<Conversations>(conf)->set(convo::one_to_one{*convo});
}
LIBSESSION_C_API void convos_set_open(config_object* conf, const convo_open_group* convo) {
    unbox<Conversations>(conf)->set(convo::open_group{*convo});
}
LIBSESSION_C_API void convos_set_legacy_closed(
        config_object* conf, const convo_legacy_closed_group* convo) {
    unbox<Conversations>(conf)->set(convo::legacy_closed_group{*convo});
}

LIBSESSION_C_API bool convos_erase_1to1(config_object* conf, const char* session_id) {
    try {
        return unbox<Conversations>(conf)->erase_1to1(session_id);
    } catch (...) {
        return false;
    }
}
LIBSESSION_C_API bool convos_erase_open(
        config_object* conf, const char* base_url, const char* room, unsigned const char* pubkey) {
    try {
        return unbox<Conversations>(conf)->erase_open(base_url, room, ustring_view{pubkey, 32});
    } catch (...) {
        return false;
    }
}
LIBSESSION_C_API bool convos_erase_legacy_closed(config_object* conf, const char* group_id) {
    try {
        return unbox<Conversations>(conf)->erase_legacy_closed(group_id);
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API size_t convos_size(const config_object* conf) {
    return unbox<Conversations>(conf)->size();
}
LIBSESSION_C_API size_t convos_size_1to1(const config_object* conf) {
    return unbox<Conversations>(conf)->size_1to1();
}
LIBSESSION_C_API size_t convos_size_open(const config_object* conf) {
    return unbox<Conversations>(conf)->size_open();
}
LIBSESSION_C_API size_t convos_size_legacy_closed(const config_object* conf) {
    return unbox<Conversations>(conf)->size_legacy_closed();
}

LIBSESSION_C_API convos_iterator* convos_iterator_new(const config_object* conf) {
    auto* it = new convos_iterator{};
    it->_internals = new Conversations::iterator{unbox<Conversations>(conf)->begin()};
    return it;
}

LIBSESSION_C_API convos_iterator* convos_iterator_new_1to1(const config_object* conf) {
    auto* it = new convos_iterator{};
    it->_internals = new Conversations::iterator{unbox<Conversations>(conf)->begin_1to1()};
    return it;
}
LIBSESSION_C_API convos_iterator* convos_iterator_new_open(const config_object* conf) {
    auto* it = new convos_iterator{};
    it->_internals = new Conversations::iterator{unbox<Conversations>(conf)->begin_open()};
    return it;
}
LIBSESSION_C_API convos_iterator* convos_iterator_new_legacy_closed(const config_object* conf) {
    auto* it = new convos_iterator{};
    it->_internals = new Conversations::iterator{unbox<Conversations>(conf)->begin_legacy_closed()};
    return it;
}

LIBSESSION_C_API void convos_iterator_free(convos_iterator* it) {
    delete static_cast<Conversations::iterator*>(it->_internals);
    delete it;
}

LIBSESSION_C_API bool convos_iterator_done(convos_iterator* it) {
    auto& real = *static_cast<Conversations::iterator*>(it->_internals);
    return real.done();
}

LIBSESSION_C_API void convos_iterator_advance(convos_iterator* it) {
    ++*static_cast<Conversations::iterator*>(it->_internals);
}

namespace {
template <typename Cpp, typename C>
bool convos_it_is_impl(convos_iterator* it, C* c) {
    auto& convo = **static_cast<Conversations::iterator*>(it->_internals);
    if (auto* d = std::get_if<Cpp>(&convo)) {
        d->into(*c);
        return true;
    }
    return false;
}
}  // namespace

LIBSESSION_C_API bool convos_it_is_1to1(convos_iterator* it, convo_one_to_one* c) {
    return convos_it_is_impl<convo::one_to_one>(it, c);
}

LIBSESSION_C_API bool convos_it_is_open(convos_iterator* it, convo_open_group* c) {
    return convos_it_is_impl<convo::open_group>(it, c);
}

LIBSESSION_C_API bool convos_it_is_legacy_closed(
        convos_iterator* it, convo_legacy_closed_group* c) {
    return convos_it_is_impl<convo::legacy_closed_group>(it, c);
}

LIBSESSION_C_API void convos_iterator_erase(config_object* conf, convos_iterator* it) {
    auto& real = *static_cast<Conversations::iterator*>(it->_internals);
    real = unbox<Conversations>(conf)->erase(real);
}

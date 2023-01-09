#include "session/config/base.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/utils.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "session/config/base.h"
#include "session/config/encrypt.hpp"
#include "session/export.h"
#include "session/util.hpp"

using namespace std::literals;

namespace session::config {

MutableConfigMessage& ConfigBase::dirty() {
    if (_state != ConfigState::Dirty) {
        set_state(ConfigState::Dirty);
        _config = std::make_unique<MutableConfigMessage>(*_config, increment_seqno);
    }

    if (auto* mut = dynamic_cast<MutableConfigMessage*>(_config.get()))
        return *mut;
    throw std::runtime_error{"Internal error: unexpected dirty but non-mutable ConfigMessage"};
}

int ConfigBase::merge(const std::vector<ustring>& configs) {
    std::vector<ustring_view> config_views;
    config_views.reserve(configs.size());
    for (auto& c : configs)
        config_views.emplace_back(c);
    return merge(config_views);
}

int ConfigBase::merge(const std::vector<ustring_view>& configs) {

    if (_keys_size == 0)
        throw std::logic_error{"Cannot merge configs without any decryption keys"};

    const auto old_seqno = _config->seqno();
    std::vector<ustring_view> all_confs;
    all_confs.reserve(configs.size() + 1);
    // We serialize our current config and include it in the list of configs to be merged, as if it
    // had already been pushed to the server (so that this code will be identical whether or not the
    // value was pushed).
    auto mine = _config->serialize();
    all_confs.emplace_back(mine);

    std::vector<ustring> plaintexts;

    // TODO:
    // - handle zstd-compressed messages: if the decrypted data starts with a `z` (instead of a `d`)
    //   then we decompress it first.
    // - handle multipart messages.  Each part of a multipart message starts with `m` and then is
    //   immediately followed by a bt_list where:
    //   - element 0 is 'z' for a zstd-compressed message, 'p' for an uncompressed message.
    //   - element 1 is the hash of the final, uncompressed, re-assembled message.
    //   - element 2 is the numeric sequence number of the message, starting from 0.
    //   - element 3 is the total number of messages in the sequence.
    //   - element 4 is a chunk of the data.
    for (size_t ci = 0; ci < configs.size(); ci++) {
        auto& conf = configs[ci];
        std::optional<ustring> plaintext;
        bool decrypted = false;
        for (size_t i = 0; !decrypted && i < _keys_size; i++) {
            try {
                plaintexts.push_back(decrypt(conf, key(i), encryption_domain()));
                decrypted = true;
            } catch (const decrypt_error&) {
                log(LogLevel::debug,
                    "Failed to decrypt message " + std::to_string(ci) + " using key " +
                            std::to_string(i));
            }
        }
        if (!decrypted)
            log(LogLevel::warning, "Failed to decrypt message " + std::to_string(ci));
    }
    log(LogLevel::debug,
        "successfully decrypted " + std::to_string(plaintexts.size()) + " of " +
                std::to_string(configs.size()) + " incoming messages");

    for (const auto& maybe_padded : plaintexts) {
        ustring_view conf{maybe_padded};
        if (auto p = maybe_padded.find_first_not_of('\0'); p > 0 && p != std::string_view::npos)
            conf.remove_prefix(p);
        if (conf[0] == 'd') {
            // Plaintext config message, this is easy
            all_confs.push_back(conf);
        } else if (conf[0] == 'z') {
            // TODO FIXME (see above)
            log(LogLevel::warning, "decompression not yet supported!");
        } else if (conf[0] == 'm') {
            // TODO FIXME (see above)
            log(LogLevel::warning, "multi-part messages not yet supported!");
        } else {
            log(LogLevel::error,
                "invalid/unsupported config message with type " +
                        (conf[0] >= 0x20 && conf[0] <= 0x7e
                                 ? "'" + std::string{from_unsigned_sv(conf.substr(0, 1))} + "'"
                                 : "0x" + oxenc::to_hex(conf.begin(), conf.begin() + 1)));
        }
    }

    int good = all_confs.size();

    auto new_conf = std::make_unique<ConfigMessage>(
            all_confs,
            nullptr, /* FIXME for signed messages: verifier */
            nullptr, /* FIXME for signed messages: signer */
            config_lags(),
            false, /* signature not optional (if we have a verifier) */
            [&](const config_error& e) {
                good--;
                log(LogLevel::warning, e.what());
            });

    if (new_conf->seqno() != old_seqno) {
        _config = std::move(new_conf);
        set_state(_config->merged() ? ConfigState::Dirty : ConfigState::Clean);
    }
    // else: the merging affect nothing (if it had seqno would have been incremented), so don't
    // pointlessly replace the inner config object.

    return good - 1;  // -1 because we don't count the first one (reparsing ourself).
}

bool ConfigBase::needs_push() const {
    return !is_clean();
}

std::pair<ustring, seqno_t> ConfigBase::push() {
    if (_keys_size == 0)
        throw std::logic_error{"Cannot push data without an encryption key!"};

    if (is_dirty())
        set_state(ConfigState::Waiting);

    std::pair<ustring, seqno_t> ret{_config->serialize(), _config->seqno()};

    // Prefix pad with nulls:
    pad_message(ret.first);
    encrypt_inplace(ret.first, key(), encryption_domain());

    return ret;
}

void ConfigBase::confirm_pushed(seqno_t seqno) {
    // Make sure seqno hasn't changed; if it has then that means we set some other data *after* the
    // caller got the last data to push, and so we don't care about this confirmation.
    if (_state == ConfigState::Waiting && seqno == _config->seqno())
        set_state(ConfigState::Clean);
}

ustring ConfigBase::dump() {
    auto data = _config->serialize(false /* disable signing for local storage */);
    auto data_sv = from_unsigned_sv(data);
    oxenc::bt_dict d{
            {"!", static_cast<int>(_state)},
            {"$", data_sv},
    };
    if (auto extra = extra_data(); !extra.empty())
        d.emplace("+", std::move(extra));

    _needs_dump = false;
    auto dumped = oxenc::bt_serialize(d);
    return ustring{to_unsigned_sv(dumped)};
}

ConfigBase::ConfigBase(std::optional<ustring_view> dump) {
    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};
    if (!dump) {
        _config = std::make_unique<ConfigMessage>();
        return;
    }

    oxenc::bt_dict_consumer d{from_unsigned_sv(*dump)};
    if (!d.skip_until("!"))
        throw std::runtime_error{"Unable to parse dumped config data: did not find '!' state key"};
    _state = static_cast<ConfigState>(d.consume_integer<int>());

    if (!d.skip_until("$"))
        throw std::runtime_error{"Unable to parse dumped config data: did not find '$' data key"};
    if (_state == ConfigState::Dirty)
        // If we dumped dirty data then we need to reload it as a mutable config message so that the
        // seqno gets incremented.  This "wastes" one seqno value (since we didn't send the old
        // one), but that's minor and easier than extracting and restoring all the fields we set and
        // is a little more robust against failure if we actually sent it but got killed before we
        // could store a dump.
        _config = std::make_unique<MutableConfigMessage>(
                to_unsigned_sv(d.consume_string_view()),
                nullptr,  // FIXME: verifier; but maybe want to delay setting this since it
                          // shouldn't be signed?
                nullptr,  // FIXME: signer
                config_lags(),
                true /* signature optional because we don't sign the dump */);
    else
        _config = std::make_unique<ConfigMessage>(
                to_unsigned_sv(d.consume_string_view()), nullptr, nullptr, config_lags(), true);

    if (d.skip_until("+"))
        if (auto extra = d.consume_dict(); !extra.empty())
            load_extra_data(std::move(extra));
}

ConfigBase::~ConfigBase() {
    sodium_free(_keys);
}

int ConfigBase::key_count() const {
    return _keys_size;
}

bool ConfigBase::has_key(ustring_view key) const {
    if (key.size() != 32)
        throw std::invalid_argument{"invalid key given to has_key(): not 32-bytes"};

    auto* keyptr = key.data();
    for (size_t i = 0; i < _keys_size; i++)
        if (sodium_memcmp(keyptr, _keys[i].data(), KEY_SIZE) == 0)
            return true;
    return false;
}

std::vector<ustring_view> ConfigBase::get_keys() const {
    std::vector<ustring_view> ret;
    ret.reserve(_keys_size);
    for (size_t i = 0; i < _keys_size; i++)
        ret.emplace_back(_keys[i].data(), _keys[i].size());
    return ret;
}

void ConfigBase::add_key(ustring_view key, bool high_priority) {
    static_assert(
            sizeof(Key) == KEY_SIZE, "std::array appears to have some overhead which seems bad");

    if (key.size() != KEY_SIZE)
        throw std::invalid_argument{"add_key failed: key size must be 32 bytes"};

    if (_keys_size > 0 && sodium_memcmp(_keys[0].data(), key.data(), KEY_SIZE) == 0)
        return;
    else if (!high_priority && has_key(key))
        return;

    if (_keys_capacity == 0) {
        // There's not a lot of point in starting this off really small: sodium is likely going to
        // use at least a page size anyway.
        _keys_capacity = 16;
        _keys = static_cast<Key*>(sodium_allocarray(_keys_capacity, KEY_SIZE));
    }

    if (_keys_size >= _keys_capacity) {
        _keys_capacity *= 2;
        auto new_keys = static_cast<Key*>(sodium_allocarray(_keys_capacity, 32));
        if (high_priority) {
            std::memcpy(new_keys[0].data(), key.data(), KEY_SIZE);
            std::memcpy(&new_keys[1], _keys, _keys_size * KEY_SIZE);
        } else {
            std::memcpy(&new_keys[0], _keys, _keys_size * KEY_SIZE);
            std::memcpy(new_keys[_keys_size].data(), key.data(), KEY_SIZE);
        }
        sodium_free(_keys);
        _keys = new_keys;
    } else if (high_priority) {
        // shift everything up so we can insert at beginning
        std::memmove(&_keys[1], &_keys[0], _keys_size * KEY_SIZE);
        std::memcpy(_keys[0].data(), key.data(), KEY_SIZE);
    } else {
        // add at the end
        std::memcpy(_keys[_keys_size].data(), key.data(), KEY_SIZE);
    }
    _keys_size++;

    // *Slightly* suboptimal in that we might change buffers above even when we didn't need to, but
    // not worth worrying about optimizing.
    if (high_priority)
        remove_key(key, 1);
}

int ConfigBase::clear_keys() {
    int ret = _keys_size;
    _keys_size = 0;
    return ret;
}

bool ConfigBase::remove_key(ustring_view key, size_t from) {
    bool removed = false;

    for (size_t i = from; i < _keys_size; i++) {
        if (sodium_memcmp(key.data(), _keys[i].data(), KEY_SIZE) == 0) {
            if (i + 1 < _keys_size)
                std::memmove(&_keys[i], &_keys[i + 1], (_keys_size - i - 1) * KEY_SIZE);
            _keys_size--;
            removed = true;
            // Don't break, in case there are somehow duplicates in here
        }
    }
    return removed;
}

void ConfigBase::load_key(ustring_view ed25519_secretkey) {
    if (!(ed25519_secretkey.size() == 64 || ed25519_secretkey.size() == 32))
        throw std::invalid_argument{
                encryption_domain() + " requires an Ed25519 64-byte secret key or 32-byte seed"s};

    add_key(ed25519_secretkey.substr(0, 32));
}

void set_error(config_object* conf, std::string e) {
    auto& error = unbox(conf).error;
    error = std::move(e);
    conf->last_error = error.c_str();
}

void copy_out(ustring_view data, unsigned char** out, size_t* outlen) {
    assert(out && outlen);
    *outlen = data.size();
    *out = static_cast<unsigned char*>(std::malloc(data.size()));
    std::memcpy(*out, data.data(), data.size());
}

}  // namespace session::config

extern "C" {

using namespace session;
using namespace session::config;

LIBSESSION_EXPORT void config_free(config_object* conf) {
    delete conf;
}

LIBSESSION_EXPORT int16_t config_storage_namespace(const config_object* conf) {
    return static_cast<int16_t>(unbox(conf)->storage_namespace());
}

LIBSESSION_EXPORT int config_merge(
        config_object* conf, const unsigned char** configs, const size_t* lengths, size_t count) {
    auto& config = *unbox(conf);
    std::vector<ustring_view> confs;
    confs.reserve(count);
    for (size_t i = 0; i < count; i++)
        confs.emplace_back(configs[i], lengths[i]);
    return config.merge(confs);
}

LIBSESSION_EXPORT bool config_needs_push(const config_object* conf) {
    return unbox(conf)->needs_push();
}

LIBSESSION_EXPORT seqno_t config_push(config_object* conf, unsigned char** out, size_t* outlen) {
    auto& config = *unbox(conf);
    auto [data, seqno] = config.push();
    copy_out(data, out, outlen);
    return seqno;
}

LIBSESSION_EXPORT void config_confirm_pushed(config_object* conf, seqno_t seqno) {
    unbox(conf)->confirm_pushed(seqno);
}

LIBSESSION_EXPORT void config_dump(config_object* conf, unsigned char** out, size_t* outlen) {
    copy_out(unbox(conf)->dump(), out, outlen);
}

LIBSESSION_EXPORT bool config_needs_dump(const config_object* conf) {
    return unbox(conf)->needs_dump();
}

LIBSESSION_EXPORT void config_add_key(config_object* conf, const unsigned char* key) {
    unbox(conf)->add_key({key, 32});
}
LIBSESSION_EXPORT void config_add_key_low_prio(config_object* conf, const unsigned char* key) {
    unbox(conf)->add_key({key, 32}, /*high_priority=*/false);
}
LIBSESSION_EXPORT int config_clear_keys(config_object* conf) {
    return unbox(conf)->clear_keys();
}
LIBSESSION_EXPORT bool config_remove_key(config_object* conf, const unsigned char* key) {
    return unbox(conf)->remove_key({key, 32});
}
LIBSESSION_EXPORT int config_key_count(const config_object* conf) {
    return unbox(conf)->key_count();
}
LIBSESSION_EXPORT bool config_has_key(const config_object* conf, const unsigned char* key) {
    return unbox(conf)->has_key({key, 32});
}
LIBSESSION_EXPORT const unsigned char* config_key(const config_object* conf, size_t i) {
    return unbox(conf)->key(i).data();
}

LIBSESSION_EXPORT const char* config_encryption_domain(const config_object* conf) {
    return unbox(conf)->encryption_domain();
}

LIBSESSION_EXPORT void config_set_logger(
        config_object* conf, void (*callback)(config_log_level, const char*, void*), void* ctx) {
    if (!callback)
        unbox(conf)->logger = nullptr;
    else
        unbox(conf)->logger = [callback, ctx](LogLevel lvl, std::string msg) {
            callback(static_cast<config_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
}

}  // extern "C"

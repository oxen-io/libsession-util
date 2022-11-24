#include "session/config/base.hpp"

#include <vector>

#include "session/config/base.h"

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

void ConfigBase::merge(const std::vector<std::string_view>& configs) {
    const auto old_seqno = _config->seqno();
    std::vector<std::string_view> all_confs;
    all_confs.reserve(configs.size() + 1);
    // We serialize our current config and include it in the list of configs to be merged, as if it
    // had already been pushed to the server (so that this code will be identical whether or not the
    // value was pushed).
    auto mine = _config->serialize();
    all_confs.emplace_back(mine);
    all_confs.insert(all_confs.end(), configs.begin(), configs.end());

    auto new_conf = std::make_unique<ConfigMessage>(
            all_confs,
            nullptr, /* FIXME for signed messages: verifier */
            nullptr, /* FIXME for signed messages: signer */
            config_lags(),
            false, /* signature not optional (if we have a verifier) */
            [this](const config_error& e) { log(LogLevel::warning, e.what()); });

    if (new_conf->seqno() == old_seqno)
        // If we get here than the merging affect nothing (otherwise seqno would have been
        // incremented).
        return;

    _config = std::move(new_conf);
    set_state(_config->merged() ? ConfigState::Dirty : ConfigState::Clean);
}

bool ConfigBase::needs_push() const {
    return !is_clean();
}

std::pair<std::string, seqno_t> ConfigBase::push() {
    if (is_dirty())
        set_state(ConfigState::Waiting);

    return {_config->serialize(), _config->seqno()};
}

void ConfigBase::confirm_pushed(seqno_t seqno) {
    // Make sure seqno hasn't changed; if it has then that means we set some other data *after* the
    // caller got the last data to push, and so we don't care about this confirmation.
    if (_state == ConfigState::Waiting && seqno == _config->seqno())
        set_state(ConfigState::Clean);
}

std::string ConfigBase::dump() {
    oxenc::bt_dict d{
            {"!", static_cast<int>(_state)},
            {"$", _config->serialize(false /* disable signing for local storage */)},
    };
    if (auto extra = extra_data(); !extra.empty())
        d.emplace("+", std::move(extra));

    _needs_dump = false;
    return oxenc::bt_serialize(d);
}

ConfigBase::ConfigBase() {
    _config = std::make_unique<ConfigMessage>();
}

ConfigBase::ConfigBase(std::string_view dump) {
    oxenc::bt_dict_consumer d{dump};
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
                d.consume_string_view(),
                nullptr,  // FIXME: verifier; but maybe want to delay setting this since it
                          // shouldn't be signed?
                nullptr,  // FIXME: signer
                config_lags(),
                true /* signature optional because we don't sign the dump */);
    else
        _config = std::make_unique<ConfigMessage>(
                d.consume_string_view(), nullptr, nullptr, config_lags(), true);

    if (d.skip_until("+"))
        if (auto extra = d.consume_dict(); !extra.empty())
            load_extra_data(std::move(extra));
}

void set_error(config_object* conf, std::string e) {
    auto& error = unbox(conf).error;
    error = std::move(e);
    conf->last_error = error.c_str();
}

void copy_out(const std::string& data, char** out, size_t* outlen) {
    assert(out && outlen);
    *outlen = data.size();
    *out = static_cast<char*>(std::malloc(data.size()));
    std::memcpy(*out, data.c_str(), data.size());
}

}  // namespace session::config

extern "C" {

using namespace session::config;

LIBSESSION_EXPORT int16_t config_storage_namespace(const config_object* conf) {
    return static_cast<int16_t>(unbox(conf)->storage_namespace());
}

LIBSESSION_EXPORT void config_merge(
        config_object* conf, const char** configs, const size_t* lengths, size_t count) {
    auto& config = *unbox(conf);
    std::vector<std::string_view> confs;
    confs.reserve(count);
    for (size_t i = 0; i < count; i++)
        confs.emplace_back(configs[i], lengths[i]);
    config.merge(confs);
}

LIBSESSION_EXPORT bool config_needs_push(const config_object* conf) {
    return unbox(conf)->needs_push();
}

LIBSESSION_EXPORT seqno_t config_push(config_object* conf, char** out, size_t* outlen) {
    auto& config = *unbox(conf);
    auto [data, seqno] = config.push();
    copy_out(data, out, outlen);
    return seqno;
}

LIBSESSION_EXPORT void config_confirm_pushed(config_object* conf, seqno_t seqno) {
    unbox(conf)->confirm_pushed(seqno);
}

LIBSESSION_EXPORT void config_dump(config_object* conf, char** out, size_t* outlen) {
    copy_out(unbox(conf)->dump(), out, outlen);
}

LIBSESSION_EXPORT bool config_needs_dump(const config_object* conf) {
    return unbox(conf)->needs_dump();
}

}  // extern "C"

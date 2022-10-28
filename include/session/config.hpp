#pragma once

#include <oxenc/bt_serialize.h>
#include <oxenc/bt_value.h>

#include <cassert>
#include <set>
#include <variant>

namespace session::config {

// Application data data types:
using scalar = std::variant<int64_t, std::string>;

using set = std::set<scalar>;
struct dict_value;
using dict = std::map<std::string, dict_value>;
using dict_variant = std::variant<dict, set, scalar>;
struct dict_value : dict_variant {
    using dict_variant::dict_variant;
    using dict_variant::operator=;
};

class config_dict_proxy;
class config_dict_proxy_value {
    friend class config_dict_proxy;
    config_dict_proxy& dict;
    std::string key;

    config_dict_proxy_value(config_dict_proxy& dict, std::string key);

  public:
    void operator=(dict_value v);
    void erase();
};

class ConfigMessage {
  protected:
    dict orig_data_;
    std::map<int64_t, oxenc::bt_dict> lagged_diffs_;

  public:
    /// The application data
    dict data;

    using sign_callable =
            std::function<std::array<unsigned char, 64>(unsigned char* data, size_t len)>;
    using verify_callable =
            std::function<bool(unsigned char* data, size_t len, unsigned char* signature)>;

    /// The signing function; if this is set it will be called to produce a signature, and the
    /// signature added to the message when producing the final config message.  Takes a pointer
    /// to the message to sign and the message length; returns a 64-byte signature.
    sign_callable sign;

    /// The verify function; if loading a message with a signature and this is set then it will
    /// be called to verify the signature of the message.  Takes a pointer to the signing data,
    /// the data length, and a pointer to the 64-byte signature.
    verify_callable verify;

    /// How many lagged config diffs that should be carried forward to resolve conflicts,
    /// including this message.  If 0 then config messages won't have any diffs and will not be
    /// mergeable.
    int lag = 5;

    /// The seqno of this message
    int64_t seqno = 0;

    /// Basic constructor that constructs a new, empty config message.
    ConfigMessage() = default;

    /// Constructs a new ConfigMessage from this config message with an incremented seqno.  The
    /// new config message's diff will reflect changes made after this construction.
    ConfigMessage increment() const;

    // Prunes empty dicts/sets from data.  This is called automatically when serializing or
    // calculating a diff.
    void prune();

    // Returns the current diff for this data relative to its original data.  The data is pruned
    // implicitly by this call.
    oxenc::bt_dict diff();

    /// TODO: construct by merging
};

}  // namespace session::config

namespace oxenc::detail {

template <>
struct bt_serialize<session::config::dict_value> : bt_serialize<session::config::dict_variant> {};

}  // namespace oxenc::detail

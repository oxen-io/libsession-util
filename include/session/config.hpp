#pragma once

#include <oxenc/bt_value.h>

namespace session {

struct config_base {
  protected:
    oxenc::bt_dict unknown;

  public:
    virtual ~config_base() = default;

    /// Generates a bt_dict from our known fields.  This is *not* what you want for serialization
    /// because it does not preserve unknown values and is generally meant for internal use as part
    /// of serialization.
    virtual oxenc::bt_dict known_dict() const = 0;

    /// Returns a bt_dict of all fields, suitable for serialization.  The default base
    /// implementation returns a merged dict of `unknown` and `known_dict()` (which values in
    /// `known_dict()` taking precedence).
    virtual oxenc::bt_dict final_dict() const;

    /// Serializes to a unique, deterministic representation.  By default this serializes
    /// final_dict().
    virtual std::string serialize() const;
};

}  // namespace session

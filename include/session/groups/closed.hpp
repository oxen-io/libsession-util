#pragma once

#include <oxenc/bt_serialize.h>

#include <optional>
#include <string>
#include <vector>

#include "../config.hpp"
#include "../fields.hpp"
#include "closed.h"

namespace session::closed_group {

struct Info {  //: config_base {
  private:
    // This bt_dict contains any fields that we parsed on input but didn't understand.  (Typically
    // these would be from an older or newer version that has additional fields).  We keep them
    // because, when we re-serialize, we need to preserve unknown values.
    oxenc::bt_dict unknown;

  public:
    // Name, in UTF-8 bytes, and may not contain a null character.
    std::string name;
    // Optional description, in UTF-8 bytes, and may not contain a null.
    std::optional<std::string> description;
    // Optional profile pic for the group.
    std::optional<Uploaded> profile_picture;
    // The group's disappearing messages setting and timer.  The default is none.
    Disappearing disappearing_messages = {};

    /// Generates a bt_dict from our known fields.  This is *not* what you want for serialization
    /// because it does not preserve unknown values and is generally meant for internal use as part
    /// of serialization.
    oxenc::bt_dict known_dict() const;

    /// Converts this instance into its C struct representation.  This moves away the data of this
    /// instance into a new instance (contained opaquely within the C struct), and so must be called
    /// on an rvalue reference (e.g. `std::move(i).to_c()`).
    ::closed_group_info* to_c() &&;

    /// Deserializes an incoming chunk of bytes, which must be a bt-encoded dict
    static Info deserialize(std::string_view incoming);
    /// Deserializes an incoming bt_dict
    static Info deserialize(oxenc::bt_dict_consumer incoming);
};

struct Member {
    enum class Role : int { Member = 0, Admin = 1 };

    // The session ID of the member
    SessionID session_id;

    // The member's role
    Role role;

    // TODO: we may also want to bundle profile info, so that a newcomer can see name/pic of
    // existing group members.  This can get complicated/weedy, though, because what any given
    // client has for someone's profile name/pic has lots of ways to be different than someone
    // else's name/pic.
};

struct Members {

    /// Members of this closed group, sorted by pubkey.
    std::vector<Member> members;

    /// Consumes this instance into its C struct version
    ::closed_group_members* to_c() &&;

    /// Serializes to a unique, deterministic representation
    std::string serialize() const;

    /// Deserializes an incoming chunk of bytes, which must be a bt-encoded dict.
    static Members deserialize(std::string_view incoming);
    /// Deserializes an incoming bt_dict
    static Members deserialize(oxenc::bt_dict_consumer incoming);
};

}  // namespace session::closed_group

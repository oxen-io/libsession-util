#include <oxenc/bt_serialize.h>
#include <oxenc/bt_value.h>

#include <cstdlib>
#include <memory>
#include <random>

#include "session/groups/closed.hpp"

namespace session::closed_group {

closed_group_info* Info::to_c() && {
    auto info_ptr = std::make_unique<Info>(std::move(*this));
    auto& i = *info_ptr;

    return new closed_group_info{
            ._internal = info_ptr.release(),
            .name = i.name.c_str(),
            .description = i.description ? i.description->c_str() : nullptr,
            .profile_picture_url = i.profile_picture ? i.profile_picture->url.c_str() : nullptr,
            .profile_picture_key = i.profile_picture ? i.profile_picture->key.c_str() : nullptr,
            .profile_picture_key_len =
                    i.profile_picture ? static_cast<int>(i.profile_picture->key.size()) : -1,
            .disappear_mode = static_cast<int>(i.disappearing_messages.mode),
            .disappear_timer = static_cast<int>(
                    i.disappearing_messages.mode == Disappearing::Mode::None
                            ? 0
                            : i.disappearing_messages.timer.count()),
    };
}

oxenc::bt_dict Info::known_dict() const {
    oxenc::bt_dict d{{"n", name}};
    if (description)
        d["d"] = *description;
    if (profile_picture) {
        d["p"] = profile_picture->url;
        d["P"] = profile_picture->key;
    }

    return d;
}

// Intermediate object that stores a Members, plus auxiliary vectors to hold the pubkey and
// closed_group_member arrays for the C struct pointers to point into.
struct c_members_internals {
    Members members;
    std::vector<std::string> pubkey_hex;
    std::vector<closed_group_member> c_members;

    explicit c_members_internals(Members&& m) :
            members{std::move(m)},
            pubkey_hex(members.members.size()),
            c_members(members.members.size()) {

        for (size_t i = 0; i < members.members.size(); i++) {
            auto& member = members.members[i];
            c_members[i].role = static_cast<int>(members.members[i].role);
            pubkey_hex[i] = member.session_id.hex();
            c_members[i].session_id = pubkey_hex[i].c_str();
        }
    }
};

closed_group_members* Members::to_c() && {
    auto members_ptr = std::make_unique<c_members_internals>(std::move(*this));
    auto& c_members = members_ptr->c_members;

    return new closed_group_members{
            ._internal = members_ptr.release(),
            .members = c_members.data(),
            .members_len = c_members.size()};
}

}  // namespace session::closed_group

extern "C" {

void free_closed_group_info(closed_group_info* info) {
    delete static_cast<session::closed_group::Info*>(info->_internal);
    free(info);
}

void free_closed_group_members(closed_group_members* members) {
    delete static_cast<session::closed_group::c_members_internals*>(members->_internal);
    free(members);
}
}

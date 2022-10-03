#include "closed.hpp"

#include <cstdlib>

namespace session::closed_group {

closed_group_info* info::to_c() && {
    auto* info_ptr = new info{std::move(*this)};
    auto& i = *info_ptr;

    return new closed_group_info{
            ._internal = info_ptr,
            .name = i.name.c_str(),
            .description = i.description ? i.description->c_str() : nullptr,
            .profile_picture_url = i.profile_picture ? i.profile_picture->url.c_str() : nullptr,
            .profile_picture_key = i.profile_picture ? i.profile_picture->key.c_str() : nullptr,
            .profile_picture_key_len =
                    i.profile_picture ? static_cast<int>(i.profile_picture->key.size()) : -1,
            .disappear_mode = static_cast<int>(i.disappearing_messages.mode),
            .disappear_timer = static_cast<int>(
                    i.disappearing_messages.mode == disappearing::Mode::None
                            ? 0
                            : i.disappearing_messages.timer.count()),
    };
}

struct closed_group_info {
    void* _internal;

    // null-terminated (C string) name.
    const char* name;

    /// Optional null-terminated (C string) description.  Will be NULL if there is no description
    /// (note that empty-description and no-description are different).
    const char* description;

    /// Optional profile picture url; either a null-terminated C string, or NULL if no profile
    /// picture is set.
    const char* profile_picture_url;
    /// Profile description key; this is bytes that *may* contain NULLs (use ..._key_len).  Will be
    /// NULL if no profile picture is set.
    const char* profile_picture_key;
    // length of profile_picture_key bytes.  -1 if no profile picture key is set.
    int profile_picture_key_len;

    /// Disappearing messages setting.  This is an integer where:
    /// 0 = no disappearing messages
    /// 1 = delete x time after send
    /// 2 = delete x time after reading (currently not implemented for closed groups)
    int disappear_mode;

    /// The timer for disappearing messages mode.
    int disappear_timer;
};

}  // namespace session::closed_group

extern "C" {

void free_closed_group_info(closed_group_info* info) {
    delete static_cast<session::closed_group::info*>(info->_internal);
    free(info);
}
}

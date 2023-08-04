#pragma once

#include <cstdint>

namespace session::config {

enum class Namespace : std::int16_t {
    UserProfile = 2,
    Contacts = 3,
    ConvoInfoVolatile = 4,
    UserGroups = 5,

    // Groups namespaces (i.e. for config of the group itself, not one user's group settings)
    GroupInfo = 11,
    GroupMembers = 12,
};

}  // namespace session::config

#pragma once

#include <cstdint>

namespace session::config {

enum class Namespace : std::int16_t {
    UserProfile = 2,
    Contacts = 3,
    ConvoInfoVolatile = 4,
    UserGroups = 5,

    // Messages sent to a closed group:
    GroupMessages = 11,
    // Groups config namespaces (i.e. for shared config of the group itself, not one user's group
    // settings)
    GroupKeys = 12,
    GroupInfo = 13,
    GroupMembers = 14,
};

namespace {
    /// Returns a number indicating the order that messages from the specified namespace should be
    /// merged in (lower numbers shold be merged first),
    /// by merging in a specific order we can prevent certain edge-cases where data/logic between
    /// different configs could be dependant on each other (eg. there could be `ConvoInfoVolatile`
    /// data related to a new conversation which hasn't been created yet because it's associated
    /// `Contacts`/`UserGroups` message hasn't been processed; or a `GroupInfo` which was encrypted
    /// with a key included in the `GroupKeys` within the same poll)
    int namespace_merge_order(const Namespace& n) {
        if (n == Namespace::UserProfile || n == Namespace::Contacts || n == Namespace::GroupKeys)
            return 0;
        if (n == Namespace::UserGroups || n == Namespace::GroupInfo || n == Namespace::GroupMembers)
            return 1;
        if (n == Namespace::ConvoInfoVolatile)
            return 2;
        return 3;
    };

    /// Returns a number indicating the order that the config messages should be sent in, we need to
    /// send the `GroupKeys` config _before_ the `GroupInfo` and `GroupMembers` configs as they both
    /// get encrypted with the latest key and we want to avoid weird edge-cases
    int namespace_store_order(const Namespace& n) {
        if (n == Namespace::GroupKeys)
            return 0;
        return 1;
    }
}  // namespace

}  // namespace session::config

#pragma once

typedef enum NAMESPACE {
    NAMESPACE_USER_PROFILE = 2,
    NAMESPACE_CONTACTS = 3,
    NAMESPACE_CONVO_INFO_VOLATILE = 4,
    NAMESPACE_USER_GROUPS = 5,

    // Messages sent to a closed group:
    NAMESPACE_GROUP_MESSAGES = 5,
    // Groups config namespaces (i.e. for shared config of the group itself, not one user's group
    // settings)
    NAMESPACE_GROUP_KEYS = 12,
    NAMESPACE_GROUP_INFO = 13,
    NAMESPACE_GROUP_MEMBERS = 14,
} NAMESPACE;

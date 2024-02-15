#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config/base.h"
#include "config/groups/members.h"
#include "config/namespaces.h"
#include "config/profile_pic.h"
#include "export.h"

LIBSESSION_EXPORT void state_create_group(
        state_object* state,
        const char* name,
        const char* description,
        const user_profile_pic pic_,
        const config_group_member* members_,
        const size_t members_len,
        void (*callback)(
                bool success, const char* group_id, unsigned const char* group_sk, void* ctx),
        void* ctx);

LIBSESSION_EXPORT void state_approve_group(
        state_object* state, const char* group_id, unsigned const char* group_sk);

#ifdef __cplusplus
}  // extern "C"
#endif

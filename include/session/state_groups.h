#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config/groups/members.h"
#include "config/namespaces.h"
#include "config/profile_pic.h"
#include "export.h"
#include "state.h"

LIBSESSION_EXPORT void state_create_group(
        state_object* state,
        const char* name,
        size_t name_len,
        const char* description,
        size_t description_len,
        const user_profile_pic pic_,
        const state_group_member* members_,
        const size_t members_len,
        void (*callback)(
                const char* group_id,
                unsigned const char* group_sk,
                const char* error,
                const size_t error_len,
                void* ctx),
        void* ctx);

LIBSESSION_EXPORT void state_approve_group(
        state_object* state, const char* group_id, unsigned const char* group_sk);

#ifdef __cplusplus
}  // extern "C"
#endif

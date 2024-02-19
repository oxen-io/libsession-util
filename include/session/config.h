#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef int64_t seqno_t;

/// Struct containing a list of C strings.  Typically where this is returned by this API it must be
/// freed (via `free()`) when done with it.
///
/// When returned as a pointer by a libsession-util function this is allocated in such a way that
/// just the outer session_string_list can be free()d to free both the list *and* the inner `value`
/// and pointed-at values.
typedef struct session_string_list {
    char** value;  // array of null-terminated C strings
    size_t len;    // length of `value`
} session_string_list;

#ifdef __cplusplus
}
#endif

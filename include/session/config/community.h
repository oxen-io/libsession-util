#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// Maximum string length of a community base URL
extern const size_t COMMUNITY_BASE_URL_MAX_LENGTH;

// Maximum string length of a community room token
extern const size_t COMMUNITY_ROOM_MAX_LENGTH;

// Maximum string length of a full URL as produced by the community_make_full_url() function.
// Unlike the above constants, this *includes* space for a NULL string terminator.
extern const size_t COMMUNITY_FULL_URL_MAX_LENGTH;

// Parses a community URL.  Writes the canonical base url, room token, and pubkey bytes into the
// given pointers.  base_url must be at least BASE_URL_MAX_LENGTH+1; room must be at least
// ROOM_MAX_LENGTH+1; and pubkey must be (at least) 32 bytes.
//
// Returns true if the url was parsed successfully, false if parsing failed (i.e. an invalid URL).
bool community_parse_full_url(
        const char* full_url, char* base_url, char* room_token, unsigned char* pubkey);

// Produces a standard full URL from a given base_url (c string), room token (c string), and pubkey
// (fixed-length 32 byte buffer).  The full URL is written to `full_url`, which must be at least
// COMMUNITY_FULL_URL_MAX_LENGTH in size.
void community_make_full_url(
        const char* base_url, const char* room, const unsigned char* pubkey, char* full_url);

#ifdef __cplusplus
}
#endif

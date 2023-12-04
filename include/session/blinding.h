#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "export.h"

LIBSESSION_EXPORT bool session_blind15_key_pair(
    const unsigned char* ed25519_seckey,
    const unsigned char* server_pk,
    unsigned char* blinded_pk_out,
    unsigned char* blinded_sk_out);

LIBSESSION_EXPORT bool session_blind25_key_pair(
    const unsigned char* ed25519_seckey,
    const unsigned char* server_pk,
    unsigned char* blinded_pk_out,
    unsigned char* blinded_sk_out);

LIBSESSION_EXPORT bool session_blind15_sign(
    const unsigned char* ed25519_seckey,
    const unsigned char* server_pk,
    const unsigned char* msg,
    size_t msg_len,
    unsigned char* blinded_sig_out);

LIBSESSION_EXPORT bool session_id_matches_blinded_id(
    const unsigned char* session_id,
    const unsigned char* blinded_id,
    const unsigned char* server_pk);

#ifdef __cplusplus
}
#endif

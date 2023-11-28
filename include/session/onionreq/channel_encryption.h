#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>

#include "../export.h"

typedef enum ENCRYPT_TYPE {
    ENCRYPT_TYPE_AES_GCM = 0,
    ENCRYPT_TYPE_X_CHA_CHA_20 = 1,
} ENCRYPT_TYPE;

// typedef struct onion_request_snode_destination {
//     char ed25519_pubkey[65];    // in hex; 64 hex chars + null terminator.
//     char x25519_pubkey[65];     // in hex; 64 hex chars + null terminator.
// } onion_request_snode_destination;

// typedef struct onion_request_server_destination {
//     char host[268];             // null-terminated (max length 267)
//     char target[268];           // null-terminated (max length 267)
//     char protocol[5];           // http/https
//     uint16_t port;              // port to send request to (in unknown then use 443 for HTTPS and 80 for HTTP)
//     char x25519_pubkey[65];     // in hex; 64 hex chars + null terminator.
// } onion_request_server_destination;

/// API: onion_request_prepare_snode_destination
///
/// Wrapper around session::onionreq::prepare.  payload_in is binary: payload_in
/// has the length provided, destination_ed25519_pubkey and destination_x25519_pubkey
/// are both hex strings and must both be exactly 64 characters. Returns a flag indicating
/// success or failure.
///
/// Declaration:
/// ```cpp
/// UNSIGNED CHAR* onion_request_prepare_snode_destination(
///     [in]    const unsigned char*    payload_in,
///     [in]    size_t                  payload_in_len,
///     [in]    const char*             destination_ed25519_pubkey,
///     [in]    const char*             destination_x25519_pubkey,
///     [in]    const char**            ed25519_pubkeys,
///     [in]    const char**            x25519_pubkeys,
///     [in]    size_t                  pubkeys_len,
///     [out]   unsigned char**         payload_out,
///     [out]   size_t*                 payload_out_len,
///     [out]   unsigned char*          final_x25519_pubkey_out,
///     [out]   unsigned char*          final_x25519_seckey_out
/// );
/// ```
///
/// Inputs:
/// - `payload_in` -- [in] The payload to be sent in the onion request
/// - `payload_in_len` -- [in] The length of the payload_in
/// - `destination_ed25519_pubkey` -- [in] The ed25519 public key for the snode destination
/// - `destination_x25519_pubkey` -- [in] The x25519 public key for the snode destination
/// - `ed25519_pubkeys` -- [in] array of ed25519 public keys for the onion request path
/// - `x25519_pubkeys` -- [in] array of x25519 public keys for the onion request path
/// - `pubkeys_len` -- [in] number or snodes in the path
/// - `payload_out` -- [out] payload to be sent through the network, will be nullptr on error
/// - `payload_out_len` -- [out] length of payload_out if not null
/// - `final_x25519_pubkey_out` -- [out] pointer to a buffer of exactly 32 bytes where the final
/// x25519 public key used for the onion request will be written if successful
/// - `final_x25519_seckey_out` -- [out] pointer to a buffer of exactly 32 bytes where the final
/// x25519 secret key used for the onion request will be written if successful
///
/// Outputs:
/// - `bool` -- True if the onion request was successfully constructed, false if it failed. 
///   If (and only if) true is returned then `payload_out` must be freed when done with it.
LIBSESSION_EXPORT bool onion_request_prepare_snode_destination(
    const unsigned char* payload_in,
    size_t payload_in_len,
    const char* destination_ed25519_pubkey,
    const char* destination_x25519_pubkey,
    const char** ed25519_pubkeys,
    const char** x25519_pubkeys,
    size_t pubkeys_len,
    unsigned char** payload_out,
    size_t* payload_out_len,
    unsigned char* final_x25519_pubkey_out,
    unsigned char* final_x25519_seckey_out
);

/// API: onion_request_prepare_server_destination
///
/// Wrapper around session::onionreq::prepare.  payload_in is binary: payload_in
/// has the length provided, destination_x25519_pubkey is a hex string and must be
/// exactly 64 characters. Returns a flag indicating success or failure.
///
/// Declaration:
/// ```cpp
/// UNSIGNED CHAR* onion_request_prepare_server_destination(
///     [in]    const unsigned char*    payload_in,
///     [in]    size_t                  payload_in_len,
///     [in]    const char*             destination_host,
///     [in]    const char*             destination_target,
///     [in]    const char*             destination_protocol,
///     [in]    uint16_t                destination_port,
///     [in]    const char*             destination_x25519_pubkey,
///     [in]    const char**            ed25519_pubkeys,
///     [in]    const char**            x25519_pubkeys,
///     [in]    size_t                  pubkeys_len,
///     [out]   unsigned char**         payload_out,
///     [out]   size_t*                 payload_out_len,
///     [out]   unsigned char*          final_x25519_pubkey_out,
///     [out]   unsigned char*          final_x25519_seckey_out
/// );
/// ```
///
/// Inputs:
/// - `payload_in` -- [in] The payload to be sent in the onion request
/// - `payload_in_len` -- [in] The length of the payload_in
/// - `destination_host` -- [in] The host for the server destination
/// - `destination_target` -- [in] The target (endpoint) for the server destination
/// - `destination_protocol` -- [in] The protocol to use for the 
/// - `destination_port` -- [in] The host for the server destination
/// - `destination_x25519_pubkey` -- [in] The x25519 public key for the server destination
/// - `ed25519_pubkeys` -- [in] array of ed25519 public keys for the onion request path
/// - `x25519_pubkeys` -- [in] array of x25519 public keys for the onion request path
/// - `pubkeys_len` -- [in] number or snodes in the path
/// - `payload_out` -- [out] payload to be sent through the network, will be nullptr on error
/// - `payload_out_len` -- [out] length of payload_out if not null
/// - `final_x25519_pubkey_out` -- [out] pointer to a buffer of exactly 32 bytes where the final
/// x25519 public key used for the onion request will be written if successful
/// - `final_x25519_seckey_out` -- [out] pointer to a buffer of exactly 32 bytes where the final
/// x25519 secret key used for the onion request will be written if successful
///
/// Outputs:
/// - `bool` -- True if the onion request was successfully constructed, false if it failed. 
///   If (and only if) true is returned then `payload_out` must be freed when done with it.
LIBSESSION_EXPORT bool onion_request_prepare_server_destination(
    const unsigned char* payload_in,
    size_t payload_in_len,
    const char* destination_host,
    const char* destination_target,
    const char* destination_protocol,
    uint16_t destination_port,
    const char* destination_x25519_pubkey,
    const char** ed25519_pubkeys,
    const char** x25519_pubkeys,
    size_t pubkeys_len,
    unsigned char** payload_out,
    size_t* payload_out_len,
    unsigned char* final_x25519_pubkey_out,
    unsigned char* final_x25519_seckey_out
);

/// API: onion_request_decrypt
///
/// Wrapper around session::onionreq::decrypt.  ciphertext_in is binary.
/// destination_x25519_pubkey, final_x25519_pubkey and final_x25519_seckey
/// should be in bytes and be exactly 32 bytes. Returns a flag indicating
/// success or failure.
///
/// Declaration:
/// ```cpp
/// bool onion_request_decrypt(
///     [in]    const unsigned char*    ciphertext,
///     [in]    size_t                  ciphertext_len,
///     [in]    const char*             destination_x25519_pubkey,
///     [in]    const char*             final_x25519_pubkey,
///     [in]    const char*             final_x25519_seckey,
///     [out]   unsigned char**         plaintext_out,
///     [out]   size_t*                 plaintext_out_len
/// );
/// ```
///
/// Inputs:
/// - `ciphertext` -- [in] The onion request response data
/// - `ciphertext_len` -- [in] The length of ciphertext
/// - `destination_x25519_pubkey` -- [in] The x25519 public key for the server destination
/// - `final_x25519_pubkey` -- [in] The final x25519 public key used for the onion request
/// - `final_x25519_seckey` -- [in] The final x25519 secret key used for the onion request
/// - `plaintext_out` -- [out] decrypted content contained within ciphertext, will be nullptr on error
/// - `plaintext_out_len` -- [out] length of plaintext_out if not null
///
/// Outputs:
/// - `bool` -- True if the onion request was successfully constructed, false if it failed. 
///   If (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool onion_request_decrypt(
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    unsigned char* destination_x25519_pubkey,
    unsigned char* final_x25519_pubkey,
    unsigned char* final_x25519_seckey,
    unsigned char** plaintext_out,
    size_t* plaintext_out_len
);
        
#ifdef __cplusplus
}
#endif
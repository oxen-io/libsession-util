#pragma once

#include <array>
#include <cstddef>
#include <exception>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "types.hpp"
#include "util.hpp"

// Helper functions for implementing multiply encrypted messages by creating separate copies of the
// message for each message recipient.  This is used most prominently in group key update messages
// to send a copy of the symmetric encryption key to each of a set of recipients.
//
// Details:
// - we use xchacha20-poly1305 encryption
// - we use a single nonce for all the encryptions (rather than a separate one for each encrypted
//   copy).  Since we are use separate keys for each encryption, nonce reuse is not a concern.
// - we support padding with optional junk entries
// - we do not sign or identify the creator of the encrypted values here (i.e. it's the caller's
//   responsibility to do that, if needed).
// - the encryption key for sender a/A, recipient b/B is: H(aB || A || B) = H(bA || A || B), and so
//   the recipient needs to know the sender's pubkey to decrypt the message.
// - the general idea is for a potential recipient to brute-force attempt to decrypt all the
//   messages to see if any work.
// - this approach is really only meant for limited size groups and is not intended for large scale.

namespace session {

namespace detail {

    void encrypt_multi_key(
            std::array<unsigned char, 32>& key_out,
            const unsigned char* a,
            const unsigned char* A,
            const unsigned char* B,
            bool encrypting,
            std::string_view domain);

    void encrypt_multi_impl(
            ustring& out,
            ustring_view message,
            const unsigned char* key,
            const unsigned char* nonce);

    bool decrypt_multi_impl(
            ustring& out,
            ustring_view ciphertext,
            const unsigned char* key,
            const unsigned char* nonce);

    inline void validate_multi_fields(
            ustring_view nonce, ustring_view privkey, ustring_view pubkey) {
        if (nonce.size() < 24)
            throw std::logic_error{"nonce must be 24 bytes"};
        if (privkey.size() != 32)
            throw std::logic_error{"privkey must be 32 bytes"};
        if (pubkey.size() != 32)
            throw std::logic_error{"pubkey requires a 32-byte pubkey"};
    }

}  // namespace detail

/// API: crypto/encrypt_multiple_message_overhead
///
/// The number of bytes of overhead required per encrypted copy of the message as produced by
/// `encrypt_for_multiple`.  This does not include the nonce or other data (such as the sender)
/// that likely needs to be transmitted as well.
extern const size_t encrypt_multiple_message_overhead;

/// API: crypto/encrypt_for_multiple
///
/// Encrypts a message multiple times for multiple recipients.  `callable` is invoked once per
/// encrypted (or junk) value, passed as a `ustring_view`.
///
/// Inputs:
/// - `messages` -- a vector of message bodies to encrypt.  Must be either size 1, or of the same
///   size as recipients.  If given a single message then that message is re-encrypted for each
///   recipient; if given multiple messages then the nth message is encrypted for the nth recipient.
///   See also session/util.hpp for a convenience function for converting other containers of
///   string-like values to this view vector type.
/// - `nonce` -- must be 24 bytes (can be longer, but only the first 24 will be used).  Should be
///   secure random, or a cryptographically secure hash incorporating secret data.  The nonce should
///   not be reused (if the same sender/recipient encryption/decryption key.
/// - `privkey` -- the sender's X25519 private key.  Must be 32 bytes.  *NOT* an Ed25519 secret key:
///   if that's what you have, you need to convert the privkey to X25519 first.
/// - `pubkey` -- the sender's X25519 public key.  Can be empty to compute it from `privkey`.
/// - `recipients` -- vector of recipient X25519 public keys.  Must be 32 bytes each (remove the 05
///   if a session id).  *NOT* Ed25519 pubkeys; conversion to X25519 may be required if that's what
///   you have.
/// - `domain` -- some unique fixed string known to both sides; this is used in the hashing function
///   used to generate individual keys for domain separation, and so should ideally have a different
///   value in different contexts (i.e. group keys uses one value, kicked messages use another,
///   etc.).  *Can* be empty, but should be set to something.
/// - `call` -- this is invoked for each different encrypted value with a ustring_view; the caller
///   must copy as needed as the ustring_view doesn't remain valid past the call.
/// - `ignore_invalid_recipient` -- if given and true then any recipients that appear to have
///   invalid public keys (i.e. the shared key multiplication fails) will be silently ignored (the
///   callback will not be called).  If not given (or false) then such a failure for any recipient
///   will raise an exception.
template <typename F>
void encrypt_for_multiple(
        const std::vector<ustring_view> messages,
        const std::vector<ustring_view> recipients,
        ustring_view nonce,
        ustring_view privkey,
        ustring_view pubkey,
        std::string_view domain,
        F&& call,
        bool ignore_invalid_recipient = false) {

    detail::validate_multi_fields(nonce, privkey, pubkey);

    for (const auto& r : recipients)
        if (r.size() != 32)
            throw std::logic_error{"encrypt_for_multiple requires 32-byte recipients pubkeys"};
    if (messages.size() != 1 && messages.size() != recipients.size())
        throw std::logic_error{
                "encrypt_for_multiple requires either 1 or recipients.size() messages"};

    size_t max_msg_size = 0;
    for (const auto& m : messages)
        if (auto sz = m.size(); sz > max_msg_size)
            max_msg_size = sz;

    ustring encrypted;
    encrypted.reserve(max_msg_size + encrypt_multiple_message_overhead);

    sodium_cleared<std::array<unsigned char, 32>> key;
    auto msg_it = messages.begin();
    for (const auto& r : recipients) {
        const auto& m = *msg_it;
        if (messages.size() > 1)
            ++msg_it;
        try {
            detail::encrypt_multi_key(key, privkey.data(), pubkey.data(), r.data(), true, domain);
        } catch (const std::exception&) {
            if (ignore_invalid_recipient)
                continue;
            else
                throw;
        }
        detail::encrypt_multi_impl(encrypted, m, key.data(), nonce.data());
        call(ustring_view{encrypted});
    }
}

/// Wrapper for passing a single message for all recipients; all arguments other than the first are
/// identical.
template <typename... Args>
void encrypt_for_multiple(ustring_view message, Args&&... args) {
    return encrypt_for_multiple(
            to_view_vector(&message, &message + 1), std::forward<Args>(args)...);
}
template <typename... Args>
void encrypt_for_multiple(std::string_view message, Args&&... args) {
    return encrypt_for_multiple(to_unsigned_sv(message), std::forward<Args>(args)...);
}
template <typename... Args>
void encrypt_for_multiple(std::basic_string_view<std::byte> message, Args&&... args) {
    return encrypt_for_multiple(to_unsigned_sv(message), std::forward<Args>(args)...);
}

/// API: crypto/decrypt_for_multiple
///
/// Decryption via a lambda: we call the lambda (which must return a std::optional<ustring_view>)
/// repeatedly until we get back a nullopt, and attempt to decrypt each returned value.  When
/// decryption succeeds, we return the plaintext to the caller.  If none of the fed-in values can be
/// decrypt, we return std::nullopt.
///
/// Inputs:
/// - `ciphertext` -- callback that returns a std::optional<ustring> or std::optional<ustring_view>
///   when called, containing the next ciphertext; should return std::nullopt when finished.
/// - `nonce` -- the nonce used for encryption/decryption (which must have been provided by the
///   sender alongside the encrypted messages, and is the same as the `nonce` value given to
///   `encrypt_for_multiple`)
/// - `privkey` -- the private X25519 key of the recipient.
/// - `pubkey` -- the public X25519 key of the recipient (for a successful decryption, this will be
///   one of the pubkeys given to `encrypt_for_multiple`.
/// - `sender_pubkey` -- the public X25519 key of the sender (this is the `pubkey` passed into
///   `encrypt_for_multiple`).
/// - `domain` -- the encryption domain; this is typically a hard-coded string, and must be the same
///   as the one used for encryption.
template <
        typename NextCiphertext,
        typename = std::enable_if_t<
                std::is_invocable_r_v<std::optional<ustring_view>, NextCiphertext> ||
                std::is_invocable_r_v<std::optional<ustring>, NextCiphertext> ||
                std::is_invocable_r_v<std::optional<std::string_view>, NextCiphertext> ||
                std::is_invocable_r_v<std::optional<std::string>, NextCiphertext> ||
                std::is_invocable_r_v<
                        std::optional<std::basic_string_view<std::byte>>,
                        NextCiphertext> ||
                std::is_invocable_r_v<std::optional<std::basic_string<std::byte>>, NextCiphertext>>>
std::optional<ustring> decrypt_for_multiple(
        NextCiphertext next_ciphertext,
        ustring_view nonce,
        ustring_view privkey,
        ustring_view pubkey,
        ustring_view sender_pubkey,
        std::string_view domain) {

    detail::validate_multi_fields(nonce, privkey, pubkey);
    if (sender_pubkey.size() != 32)
        throw std::logic_error{"pubkey requires a 32-byte pubkey"};

    sodium_cleared<std::array<unsigned char, 32>> key;
    detail::encrypt_multi_key(
            key, privkey.data(), pubkey.data(), sender_pubkey.data(), false, domain);

    auto decrypted = std::make_optional<ustring>();

    for (auto ciphertext = next_ciphertext(); ciphertext; ciphertext = next_ciphertext())
        if (detail::decrypt_multi_impl(*decrypted, *ciphertext, key.data(), nonce.data()))
            return decrypted;

    decrypted.reset();
    return decrypted;
}

/// API: crypto/decrypt_for_multiple
///
/// Attempts to decrypt any of the messages produced by `encrypt_for_multiple`.  As soon as one
/// decrypts successfully it is returned.  If non decrypt you get back std::nullopt.
///
/// Inputs:
/// - `ciphertexts` -- the encrypted values
/// - `nonce` -- the nonce used for encryption/decryption (which must have been provided by the
///   sender alongside the encrypted messages, and is the same as the `nonce` value given to
///   `encrypt_for_multiple`)
/// - `privkey` -- the private X25519 key of the recipient.
/// - `pubkey` -- the public X25519 key of the recipient (for a successful decryption, this will be
///   one of the pubkeys given to `encrypt_for_multiple`.
/// - `sender_pubkey` -- the public X25519 key of the sender (this is the `pubkey` passed into
///   `encrypt_for_multiple`).
/// - `domain` -- the encryption domain; this is typically a hard-coded string, and must be the same
///   as the one used for encryption.
///
std::optional<ustring> decrypt_for_multiple(
        const std::vector<ustring_view>& ciphertexts,
        ustring_view nonce,
        ustring_view privkey,
        ustring_view pubkey,
        ustring_view sender_pubkey,
        std::string_view domain);



}  // namespace session

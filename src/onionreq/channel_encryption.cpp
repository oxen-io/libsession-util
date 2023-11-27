#include "session/onionreq/channel_encryption.hpp"

#include <nettle/gcm.h>
#include <oxenc/hex.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <nlohmann/json.hpp>
#include <exception>
#include <iostream>
#include <memory>

#include "session/xed25519.hpp"
#include "session/onionreq/channel_encryption.h"
#include "session/onionreq/key_types.hpp"
#include "session/export.h"
#include "session/util.hpp"

namespace session::onionreq {

namespace {

    // Derive shared secret from our (ephemeral) `seckey` and the other party's `pubkey`
    std::array<uint8_t, crypto_scalarmult_BYTES> calculate_shared_secret(
            const x25519_seckey& seckey, const x25519_pubkey& pubkey) {
        std::array<uint8_t, crypto_scalarmult_BYTES> secret;
        if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0)
            throw std::runtime_error("Shared key derivation failed (crypto_scalarmult)");
        return secret;
    }

    constexpr std::string_view salt{"LOKI"};

    std::array<uint8_t, crypto_scalarmult_BYTES> derive_symmetric_key(
            const x25519_seckey& seckey, const x25519_pubkey& pubkey) {
        auto key = calculate_shared_secret(seckey, pubkey);

        auto usalt = to_unsigned_sv(salt);

        crypto_auth_hmacsha256_state state;

        crypto_auth_hmacsha256_init(&state, usalt.data(), usalt.size());
        crypto_auth_hmacsha256_update(&state, key.data(), key.size());
        crypto_auth_hmacsha256_final(&state, key.data());

        return key;
    }

    // More robust shared secret calculation, used when using xchacha20-poly1305 encryption.  (This
    // could be used for AES-GCM as well, but would break backwards compatibility with existing
    // Session clients).
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> xchacha20_shared_key(
            const x25519_pubkey& local_pub,
            const x25519_seckey& local_sec,
            const x25519_pubkey& remote_pub,
            bool local_first) {
        std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key;
        static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES >= crypto_scalarmult_BYTES);
        if (0 != crypto_scalarmult(
                         key.data(),
                         local_sec.data(),
                         remote_pub.data()))  // Use key as tmp storage for aB
            throw std::runtime_error{"Failed to compute shared key for xchacha20"};
        crypto_generichash_state h;
        crypto_generichash_init(&h, nullptr, 0, key.size());
        crypto_generichash_update(&h, key.data(), crypto_scalarmult_BYTES);
        crypto_generichash_update(
                &h, (local_first ? local_pub : remote_pub).data(), local_pub.size());
        crypto_generichash_update(
                &h, (local_first ? remote_pub : local_pub).data(), local_pub.size());
        crypto_generichash_final(&h, key.data(), key.size());
        return key;
    }

    ustring encode_size(uint32_t s) {
        ustring str{reinterpret_cast<const unsigned char*>(&s), 4};
        return str;
    }

    std::basic_string_view<unsigned char> to_uchar(std::string_view sv) {
        return {reinterpret_cast<const unsigned char*>(sv.data()), sv.size()};
    }

    std::string from_ustring(ustring us) {
        return {reinterpret_cast<const char*>(us.data()), us.size()};
    }

}  // namespace

EncryptType parse_enc_type(std::string_view enc_type) {
    if (enc_type == "xchacha20" || enc_type == "xchacha20-poly1305")
        return EncryptType::xchacha20;
    if (enc_type == "aes-gcm" || enc_type == "gcm")
        return EncryptType::aes_gcm;
    throw std::runtime_error{"Invalid encryption type " + std::string{enc_type}};
}

ustring ChannelEncryption::encrypt(
        EncryptType type, ustring plaintext, const x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return encrypt_xchacha20(plaintext, pubkey);
        case EncryptType::aes_gcm: return encrypt_aesgcm(plaintext, pubkey);
    }
    throw std::runtime_error{"Invalid encryption type"};
}

ustring ChannelEncryption::decrypt(
        EncryptType type, ustring ciphertext, const x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return decrypt_xchacha20(ciphertext, pubkey);
        case EncryptType::aes_gcm: return decrypt_aesgcm(ciphertext, pubkey);
    }
    throw std::runtime_error{"Invalid decryption type"};
}

ustring ChannelEncryption::encrypt_aesgcm(
        ustring plaintext, const x25519_pubkey& pubKey) const {
    auto key = derive_symmetric_key(private_key_, pubKey);

    // Initialise cipher context with the key
    struct gcm_aes256_ctx ctx;
    static_assert(key.size() == AES256_KEY_SIZE);
    gcm_aes256_set_key(&ctx, key.data());

    ustring output;
    output.resize(GCM_IV_SIZE + plaintext.size() + GCM_DIGEST_SIZE);

    // Start the output with the random IV, and load it into ctx
    auto* o = output.data();
    randombytes_buf(o, GCM_IV_SIZE);
    gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, o);
    o += GCM_IV_SIZE;

    // Append encrypted data
    gcm_aes256_encrypt(&ctx, plaintext.size(), o, plaintext.data());
    o += plaintext.size();

    // Append digest
    gcm_aes256_digest(&ctx, GCM_DIGEST_SIZE, o);
    o += GCM_DIGEST_SIZE;

    assert(o == output.data() + output.size());

    return output;
}

ustring ChannelEncryption::decrypt_aesgcm(
        ustring ciphertext_, const x25519_pubkey& pubKey) const {
    ustring_view ciphertext = {ciphertext_.data(), ciphertext_.size()};

    if (ciphertext.size() < GCM_IV_SIZE + GCM_DIGEST_SIZE)
        throw std::runtime_error{"ciphertext data is too short"};

    auto key = derive_symmetric_key(private_key_, pubKey);

    // Initialise cipher context with the key
    struct gcm_aes256_ctx ctx;
    static_assert(key.size() == AES256_KEY_SIZE);
    gcm_aes256_set_key(&ctx, key.data());

    gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, ciphertext.data());

    ciphertext.remove_prefix(GCM_IV_SIZE);
    auto digest_in = ciphertext.substr(ciphertext.size() - GCM_DIGEST_SIZE);
    ciphertext.remove_suffix(GCM_DIGEST_SIZE);

    ustring plaintext;
    plaintext.resize(ciphertext.size());

    gcm_aes256_decrypt(&ctx, ciphertext.size(), plaintext.data(), ciphertext.data());

    std::array<uint8_t, GCM_DIGEST_SIZE> digest_out;
    gcm_aes256_digest(&ctx, digest_out.size(), digest_out.data());

    if (sodium_memcmp(digest_out.data(), digest_in.data(), GCM_DIGEST_SIZE) != 0)
        throw std::runtime_error{"Decryption failed (AES256-GCM)"};

    return plaintext;
}

ustring ChannelEncryption::encrypt_xchacha20(
        ustring plaintext, const x25519_pubkey& pubKey) const {

    ustring ciphertext;
    ciphertext.resize(
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

    const auto key = xchacha20_shared_key(public_key_, private_key_, pubKey, !server_);

    // Generate random nonce, and stash it at the beginning of ciphertext:
    randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    auto* c = reinterpret_cast<unsigned char*>(ciphertext.data()) +
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            c,
            &clen,
            plaintext.data(),
            plaintext.size(),
            nullptr,
            0,        // additional data
            nullptr,  // nsec (always unused)
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            key.data());
    assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen <= ciphertext.size());
    ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen);
    return ciphertext;
}

ustring ChannelEncryption::decrypt_xchacha20(
        ustring ciphertext_, const x25519_pubkey& pubKey) const {
    ustring_view ciphertext = {ciphertext_.data(), ciphertext_.size()};

    // Extract nonce from the beginning of the ciphertext:
    auto nonce = ciphertext.substr(0, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ciphertext.remove_prefix(nonce.size());
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error{"Invalid ciphertext: too short"};

    const auto key = xchacha20_shared_key(public_key_, private_key_, pubKey, !server_);

    ustring plaintext;
    plaintext.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    auto* m = reinterpret_cast<unsigned char*>(plaintext.data());
    unsigned long long mlen;
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     m,
                     &mlen,
                     nullptr,  // nsec (always unused)
                     ciphertext.data(),
                     ciphertext.size(),
                     nullptr,
                     0,  // additional data
                     nonce.data(),
                     key.data()))
        throw std::runtime_error{"Could not decrypt (XChaCha20-Poly1305)"};
    assert(mlen <= plaintext.size());
    plaintext.resize(mlen);
    return plaintext;
}

std::pair<ustring, x25519_keypair> prepare(
    std::string_view payload,
    destination& destination,
    std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> keys,
    std::optional<EncryptType> enc_type) {

    ustring blob;

    // First hop:
    //
    // [N][ENCRYPTED]{json}
    //
    // where json has the ephemeral_key indicating how we encrypted ENCRYPTED for this first hop.
    // The first hop decrypts ENCRYPTED into:
    //
    // [N][BLOB]{json}
    //
    // where [N] is the length of the blob and {json} now contains either:
    // - a "headers" key with an empty value.  This is how we indicate that the request is for this
    //   node as the final hop, and means that the BLOB is actually JSON it should parse to get the
    //   request info (which has "method", "params", etc. in it).
    // - "host"/"target"/"port"/"protocol" asking for an HTTP or HTTPS proxy request to be made
    //   (though "target" must start with /loki/ or /oxen/ and end with /lsrpc).  (There is still a
    //   blob here, but it is not used and typically empty).
    // - "destination" and "ephemeral_key" to forward the request to the next hop.
    //
    // This later case continues onion routing by giving us something like:
    //
    //      {"destination":"ed25519pubkey","ephemeral_key":"x25519-eph-pubkey-for-decryption","enc_type":"xchacha20"}
    //
    // (enc_type can also be aes-gcm, and defaults to that if not specified).  We forward this via
    // oxenmq to the given ed25519pubkey (but since oxenmq uses x25519 pubkeys we first have to go
    // look it up), sending an oxenmq request to sn.onion_req_v2 of the following (but bencoded, not
    // json):
    //
    //  { "d": "BLOB", "ek": "ephemeral-key-in-binary", "et": "xchacha20", "nh": N }
    //
    // where BLOB is the opaque data received from the previous hop and N is the hop number which
    // gets incremented at each hop (and terminates if it exceeds 15).  That next hop decrypts BLOB,
    // giving it a value interpreted as the same [N][BLOB]{json} as above, and we recurse.
    //
    // On the *return* trip, the message gets encrypted (once!) at the final destination using the
    // derived key from the pubkey given to the final hop, base64-encoded, then passed back without
    // any onion encryption at all all the way back to the client.

    // Ephemeral keypair:
    x25519_pubkey A;
    x25519_seckey a;
    x25519_pubkey final_pubkey;
    x25519_seckey final_seckey;
    nlohmann::json final_route;
    EncryptType etype = enc_type.value_or(EncryptType::xchacha20);
    
    {
        crypto_box_keypair(A.data(), a.data());
        ChannelEncryption e{a, A, false};

        // The data we send to the destination differs depending on whether the destination is a server
        // or a service node
        if (auto server = dynamic_cast<const server_destination*>(&destination)) {
            final_route = {
                {"host", server->host},
                {"target", server->target},
                {"method", "POST"},
                {"protocol", server->protocol},
                {"port", server->port.value_or(server->protocol == "https" ? 443 : 80)},
                {"ephemeral_key", A.hex()}, // The x25519 ephemeral_key here is the key for the *next* hop to use
                {"enc_type", to_string(etype)},
            };

            blob = e.encrypt(etype, to_uchar(payload).data(), server->x25519_public_key);
        } else if (auto snode = dynamic_cast<const snode_destination*>(&destination)) {
            nlohmann::json control{
                {"headers", ""}
            };
            final_route = {
                {"destination", snode->ed25519_public_key.hex()}, // Next hop's ed25519 key
                {"ephemeral_key", A.hex()}, // The x25519 ephemeral_key here is the key for the *next* hop to use
                {"enc_type", to_string(etype)},
            };

            auto data = encode_size(payload.size());
            data += to_uchar(payload);
            data += to_uchar(control.dump());
            blob = e.encrypt(etype, data, snode->x25519_public_key);
        } else {
            throw std::runtime_error{"Invalid destination type"};
        }

        // Save these because we need them again to decrypt the final response:
        final_seckey = a;
        final_pubkey = A;
    }
    
    for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
        // Routing data for this hop:
        nlohmann::json routing;

        if (it == keys.rbegin()) {
            routing = final_route;
        }
        else {
            routing = {
                {"destination", std::prev(it)->first.hex()}, // Next hop's ed25519 key
                {"ephemeral_key", A.hex()}, // The x25519 ephemeral_key here is the key for the *next* hop to use
                {"enc_type", to_string(etype)},
            };
        }

        auto data = encode_size(blob.size());
        data += blob;
        data += to_uchar(routing.dump());

        // Generate eph key for *this* request and encrypt it:
        crypto_box_keypair(A.data(), a.data());
        ChannelEncryption e{a, A, false};
        blob = e.encrypt(etype, data, it->second);
    }

    // The data going to the first hop needs to be wrapped in one more layer to tell the first hop
    // how to decrypt the initial payload:
    auto result = encode_size(blob.size());
    result += blob;
    result += to_uchar(nlohmann::json{
        {"ephemeral_key", A.hex()},
        {"enc_type", to_string(etype)}
    }.dump());

    return {result, {final_pubkey, final_seckey}};
}

ustring decrypt(
    ustring ciphertext,
    const x25519_pubkey destinationPubkey,
    const x25519_pubkey finalPubkey,
    const x25519_seckey finalSeckey,
    std::optional<EncryptType> enc_type) {
    ChannelEncryption d{finalSeckey, finalPubkey, false};
    EncryptType etype = enc_type.value_or(EncryptType::xchacha20);

    return d.decrypt(etype, ciphertext, destinationPubkey);
}

}  // namespace session::onionreq

extern "C" {

using session::ustring;

LIBSESSION_C_API bool onion_request_prepare_snode_destination(
    const char* payload_in,
    const char* destination_ed25519_pubkey,
    const char* destination_x25519_pubkey,
    const char** ed25519_pubkeys,
    const char** x25519_pubkeys,
    size_t pubkeys_len,
    unsigned char** payload_out,
    size_t* payload_out_len,
    unsigned char* final_x25519_pubkey_out,
    unsigned char* final_x25519_seckey_out
) {
    assert(payload_in && destination_ed25519_pubkey && destination_x25519_pubkey && ed25519_pubkeys && x25519_pubkeys);

    session::onionreq::snode_destination destination = {
        session::onionreq::ed25519_pubkey::from_hex({destination_ed25519_pubkey, 64}),
        session::onionreq::x25519_pubkey::from_hex({destination_x25519_pubkey, 64})
    };
    std::vector<std::pair<session::onionreq::ed25519_pubkey, session::onionreq::x25519_pubkey>> keys;
    for (size_t i = 0; i < pubkeys_len; i++)
        keys.emplace_back(
            session::onionreq::ed25519_pubkey::from_hex({ed25519_pubkeys[i], 64}),
            session::onionreq::x25519_pubkey::from_hex({x25519_pubkeys[i], 64})
        );
    
    try {
        auto result = session::onionreq::prepare(
            payload_in,
            destination,
            keys,
            session::onionreq::EncryptType::aes_gcm// xchacha20
        );
        
        auto [payload, final_key_pair] = result;
        *payload_out = static_cast<unsigned char*>(malloc(payload.size()));
        *payload_out_len = payload.size();
        std::memcpy(*payload_out, payload.data(), payload.size());
        std::memcpy(final_x25519_pubkey_out, final_key_pair.first.data(), final_key_pair.first.size());
        std::memcpy(final_x25519_seckey_out, final_key_pair.second.data(), final_key_pair.second.size());
        return true;
    }
    catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool onion_request_prepare_server_destination(
    const char* payload_in,
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
) {
    assert(payload_in && destination_x25519_pubkey && ed25519_pubkeys && x25519_pubkeys);

    session::onionreq::server_destination destination = {
        destination_host,
        destination_target,
        destination_protocol,
        destination_port,
        session::onionreq::x25519_pubkey::from_hex({destination_x25519_pubkey, 64})
    };
    std::vector<std::pair<session::onionreq::ed25519_pubkey, session::onionreq::x25519_pubkey>> keys;
    for (size_t i = 0; i < pubkeys_len; i++)
        keys.emplace_back(
            session::onionreq::ed25519_pubkey::from_hex({ed25519_pubkeys[i], 64}),
            session::onionreq::x25519_pubkey::from_hex({x25519_pubkeys[i], 64})
        );
    
    try {
        auto result = session::onionreq::prepare(
            payload_in,
            destination,
            keys,
            session::onionreq::EncryptType::aes_gcm// xchacha20
        );
        
        auto [payload, final_key_pair] = result;
        *payload_out = static_cast<unsigned char*>(malloc(payload.size()));
        *payload_out_len = payload.size();
        std::memcpy(*payload_out, payload.data(), payload.size());
        std::memcpy(final_x25519_pubkey_out, final_key_pair.first.data(), final_key_pair.first.size());
        std::memcpy(final_x25519_seckey_out, final_key_pair.second.data(), final_key_pair.second.size());
        return true;
    }
    catch (...) { 
        return false;
    }
}

LIBSESSION_C_API bool onion_request_decrypt(
    const unsigned char* ciphertext_in,
    const char* destination_x25519_pubkey,
    unsigned char* final_x25519_pubkey,
    unsigned char* final_x25519_seckey,
    unsigned char** plaintext_out,
    size_t* plaintext_out_len
) {
    assert(ciphertext_in && destination_x25519_pubkey && final_x25519_pubkey && final_x25519_seckey);

    try {
        auto result = session::onionreq::decrypt(
            ciphertext_in,
            session::onionreq::x25519_pubkey::from_hex({destination_x25519_pubkey, 64}),
            session::onionreq::x25519_pubkey::from_bytes({final_x25519_pubkey, 32}),
            session::onionreq::x25519_seckey::from_bytes({final_x25519_seckey, 32}),
            session::onionreq::EncryptType::xchacha20
        );
    }
    catch (...) { 
        return false;
    }
}

}

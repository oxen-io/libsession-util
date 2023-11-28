#pragma once

#include <string>
#include <string_view>

#include "key_types.hpp"

namespace session::onionreq {

enum class EncryptType {
    aes_gcm,
    xchacha20,
};

// Takes the encryption type as a string, returns the EncryptType value (or throws if invalid).
// Supported values: aes-gcm and xchacha20.  gcm is accepted as an aliases for aes-gcm.
EncryptType parse_enc_type(std::string_view enc_type);

inline constexpr std::string_view to_string(EncryptType type) {
    switch (type) {
        case EncryptType::xchacha20: return "xchacha20"sv;
        case EncryptType::aes_gcm: return "aes-gcm"sv;
    }
    return ""sv;
}

struct destination {
    x25519_pubkey x25519_public_key;

    destination(x25519_pubkey public_key) : x25519_public_key{std::move(public_key)} {}

    virtual ~destination() = default;
};

struct snode_destination: public destination {
    ed25519_pubkey ed25519_public_key;

    snode_destination(ed25519_pubkey ed25519_public_key, x25519_pubkey public_key) :
      destination(public_key), ed25519_public_key{std::move(ed25519_public_key)} {}
};

struct server_destination : public destination {
    std::string host;
    std::string target;
    std::string protocol;
    std::optional<uint16_t> port;

    server_destination(std::string&& host, std::string&& target, std::string&& protocol, std::optional<uint16_t> port,
      x25519_pubkey public_key) :
        destination(public_key),
        host{std::move(host)},
        target{std::move(target)},
        protocol{std::move(protocol)},
        port{port} {}
};

// Encryption/decription class for encryption/decrypting outgoing/incoming messages.
class ChannelEncryption {
  public:
    ChannelEncryption(x25519_seckey private_key, x25519_pubkey public_key, bool server = true) :
            private_key_{std::move(private_key)},
            public_key_{std::move(public_key)},
            server_{server} {}

    // Encrypts `plaintext` message using encryption `type`. `pubkey` is the recipients public key.
    // `reply` should be false for a client-to-snode message, and true on a returning
    // snode-to-client message.
    ustring encrypt(EncryptType type, ustring plaintext, const x25519_pubkey& pubkey) const;
    ustring decrypt(EncryptType type, ustring ciphertext, const x25519_pubkey& pubkey) const;

    // AES-GCM encryption.
    ustring encrypt_aesgcm(ustring plainText, const x25519_pubkey& pubKey) const;
    ustring decrypt_aesgcm(ustring cipherText, const x25519_pubkey& pubKey) const;

    // xchacha20-poly1305 encryption; for a message sent from client Alice to server Bob we use a
    // shared key of a Blake2B 32-byte (i.e. crypto_aead_xchacha20poly1305_ietf_KEYBYTES) hash of
    // H(aB || A || B), which Bob can compute when receiving as H(bA || A || B).  The returned value
    // always has the crypto_aead_xchacha20poly1305_ietf_NPUBBYTES nonce prepended to the beginning.
    //
    // When Bob (the server) encrypts a method for Alice (the client), he uses shared key
    // H(bA || A || B) (note that this is *different* that what would result if Bob was a client
    // sending to Alice the client).
    ustring encrypt_xchacha20(ustring plaintext, const x25519_pubkey& pubKey) const;
    ustring decrypt_xchacha20(ustring ciphertext, const x25519_pubkey& pubKey) const;

  private:
    const x25519_seckey private_key_;
    const x25519_pubkey public_key_;
    bool server_;  // True if we are the server (i.e. the snode).
};

std::pair<ustring, x25519_keypair> prepare(
    ustring payload,
    destination& destination,
    std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> keys,
    std::optional<EncryptType> enc_type);

ustring decrypt(
    ustring ciphertext,
    const x25519_pubkey destinationPubkey,
    const x25519_pubkey finalPubkey,
    const x25519_seckey finalSeckey,
    std::optional<EncryptType> enc_type);

}  // namespace session::onionreq


#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <session/multi_encrypt.hpp>
#include <stdexcept>

namespace session {

const size_t encrypt_multiple_message_overhead = crypto_aead_xchacha20poly1305_ietf_ABYTES;

namespace detail {

    void encrypt_multi_key(
            std::array<unsigned char, 32>& key,
            const unsigned char* a,
            const unsigned char* A,
            const unsigned char* B,
            bool encrypting,
            std::string_view domain) {

        std::array<unsigned char, 32> buf;
        if (0 != crypto_scalarmult_curve25519(buf.data(), a, B))
            throw std::invalid_argument{"Unable to compute shared encrypted key: invalid pubkey?"};

        static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == 32);

        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(
                &st,
                reinterpret_cast<const unsigned char*>(domain.data()),
                std::min<size_t>(domain.size(), crypto_generichash_blake2b_KEYBYTES_MAX),
                32);

        crypto_generichash_blake2b_update(&st, buf.data(), buf.size());

        // If we're encrypting then a/A == sender, B = recipient
        // If we're decrypting then a/A = recipient, B = sender
        // We always need the same sR || S || R or rS || S || R, so if we're decrypting we need to
        // put B before A in the hash;
        const auto* S = encrypting ? A : B;
        const auto* R = encrypting ? B : A;
        crypto_generichash_blake2b_update(&st, S, 32);
        crypto_generichash_blake2b_update(&st, R, 32);
        crypto_generichash_blake2b_final(&st, key.data(), 32);
    }

    void encrypt_multi_impl(
            ustring& out, ustring_view msg, const unsigned char* key, const unsigned char* nonce) {

        //        auto key = encrypt_multi_key(a, A, B, true, domain);

        out.resize(msg.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        if (0 !=
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                    out.data(), nullptr, msg.data(), msg.size(), nullptr, 0, nullptr, nonce, key))
            throw std::runtime_error{"XChaCha20 encryption failed!"};
    }

    bool decrypt_multi_impl(
            ustring& out,
            ustring_view ciphertext,
            const unsigned char* key,
            const unsigned char* nonce) {

        if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
            return false;

        out.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        return 0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                            out.data(),
                            nullptr,
                            nullptr,
                            ciphertext.data(),
                            ciphertext.size(),
                            nullptr,
                            0,
                            nonce,
                            key);
    }

}  // namespace detail

std::optional<ustring> decrypt_for_multiple(
        const std::vector<ustring_view>& ciphertexts,
        ustring_view nonce,
        ustring_view privkey,
        ustring_view pubkey,
        ustring_view sender_pubkey,
        std::string_view domain) {

    auto it = ciphertexts.begin();
    return decrypt_for_multiple(
            [&]() -> std::optional<ustring_view> {
                if (it == ciphertexts.end())
                    return std::nullopt;
                return *it++;
            },
            nonce,
            privkey,
            pubkey,
            sender_pubkey,
            domain);
}
}  // namespace session

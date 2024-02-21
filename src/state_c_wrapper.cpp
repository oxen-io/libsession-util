#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

#include "config/internal.hpp"
#include "session/config/base.hpp"
#include "session/config/contacts.h"
#include "session/config/contacts.hpp"
#include "session/config/convo_info_volatile.hpp"
#include "session/config/groups/members.h"
#include "session/config/namespaces.h"
#include "session/config/namespaces.hpp"
#include "session/config/user_groups.hpp"
#include "session/config/user_profile.hpp"
#include "session/export.h"
#include "session/state.h"
#include "session/state.hpp"
#include "session/state_groups.h"
#include "session/util.hpp"

using namespace std::literals;
using namespace session;
using namespace session::config;
using namespace session::state;

LIBSESSION_C_API const size_t PROFILE_PIC_MAX_URL_LENGTH = profile_pic::MAX_URL_LENGTH;

extern "C" {

// Util Functions

LIBSESSION_C_API bool session_id_is_valid(const char* session_id) {
    return std::strlen(session_id) == 66 && oxenc::is_hex(session_id, session_id + 66);
}

// State Functions

LIBSESSION_EXPORT void state_free(state_object* state) {
    delete state;
}

LIBSESSION_C_API bool state_init(
        state_object** state,
        const unsigned char* ed25519_secretkey_bytes,
        state_namespaced_dump* dumps_,
        size_t count,
        char* error) {
    try {
        std::vector<namespaced_dump> dumps = {};
        dumps.reserve(count);

        for (size_t i = 0; i < count; i++) {
            std::optional<std::string_view> pubkey_hex;

            if (dumps_[i].pubkey_hex)
                pubkey_hex.emplace(dumps_[i].pubkey_hex, 66);

            dumps.emplace_back(
                    static_cast<config::Namespace>(dumps_[i].namespace_),
                    pubkey_hex,
                    ustring{dumps_[i].data, dumps_[i].datalen});
        }

        auto s = std::make_unique<session::state::State>(
                session::ustring_view{ed25519_secretkey_bytes, 64}, dumps);
        auto s_object = std::make_unique<state_object>();

        s_object->internals = s.release();
        s_object->last_error = nullptr;
        *state = s_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error_value(error, e.what());
    }
}

LIBSESSION_C_API bool state_load(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex_,
        const unsigned char* dump,
        size_t dumplen) {
    assert(state && dump && dumplen);

    session::ustring_view dumped{dump, dumplen};
    std::optional<std::string_view> pubkey_hex;
    if (pubkey_hex_)
        pubkey_hex.emplace(pubkey_hex_, 66);

    try {
        auto target_namespace = static_cast<Namespace>(namespace_);

        unbox(state).load(target_namespace, pubkey_hex, dumped);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API void state_set_logger(
        state_object* state, void (*callback)(state_log_level, const char*, void*), void* ctx) {
    if (!callback)
        unbox(state).logger = nullptr;
    else {
        unbox(state).logger = [callback, ctx](session::config::LogLevel lvl, std::string msg) {
            callback(static_cast<state_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
    }
}

using response_callback_t =
        std::function<void(bool success, int16_t status_code, ustring response)>;
struct response_callback_info {
    state_object* state;
    response_callback_t cb;

    response_callback_info(state_object* state, response_callback_t cb) : state{state}, cb{cb} {}
};

LIBSESSION_C_API bool state_set_send_callback(
        state_object* state,
        void (*callback)(
                const char* pubkey,
                const unsigned char* data,
                size_t data_len,
                bool (*response_cb)(
                        bool success,
                        int16_t status_code,
                        const unsigned char* res,
                        size_t reslen,
                        void* callback_context),
                void* app_ctx,
                void* callback_context),
        void* app_ctx) {
    try {
        if (!callback)
            unbox(state).on_send(nullptr);
        else {
            unbox(state).on_send([state, callback, app_ctx](
                                         std::string pubkey,
                                         ustring data,
                                         response_callback_t received_response) {
                // We leak ownership of this std::function below in the `.release()` call, then we
                // recapture it inside the inner response callback below.
                auto on_response = std::make_unique<response_callback_info>(
                        state, std::move(received_response));

                callback(
                        pubkey.c_str(),
                        data.data(),
                        data.size(),
                        [](bool success,
                           int16_t status_code,
                           const unsigned char* res,
                           size_t reslen,
                           void* callback_context) {
                            // Recapture the std::function callback here in a unique_ptr so that
                            // we clean it up at the end of this lambda.
                            std::unique_ptr<response_callback_info> info{
                                    static_cast<response_callback_info*>(callback_context)};
                            try {
                                info->cb(success, status_code, {res, reslen});
                                return true;
                            } catch (const std::exception& e) {
                                return set_error(info->state, e.what());
                            }
                        },
                        app_ctx,
                        on_response.release());
            });
        }

        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API bool state_set_store_callback(
        state_object* state,
        void (*callback)(NAMESPACE, const char*, uint64_t, const unsigned char*, size_t, void*),
        void* ctx) {
    try {
        if (!callback)
            unbox(state).on_store(nullptr);
        else {
            // Setting this can result in the callback being immediately triggered which could throw
            unbox(state).on_store([callback, ctx](
                                          config::Namespace namespace_,
                                          std::string pubkey,
                                          uint64_t timestamp_ms,
                                          ustring data) {
                callback(
                        static_cast<NAMESPACE>(namespace_),
                        pubkey.c_str(),
                        timestamp_ms,
                        data.data(),
                        data.size(),
                        ctx);
            });
        }

        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API void state_set_service_node_offset(state_object* state, int64_t offset_ms) {
    unbox(state).network_offset = std::chrono::milliseconds(offset_ms);
}

LIBSESSION_C_API int64_t state_network_offset(const state_object* state) {
    return unbox(state).network_offset.count();
}

LIBSESSION_C_API bool state_has_pending_send(const state_object* state) {
    return unbox(state).has_pending_send();
}

LIBSESSION_C_API bool state_merge(
        state_object* state,
        const char* pubkey_hex_,
        state_config_message* configs,
        size_t count,
        session_string_list** successful_hashes) {
    try {
        std::optional<std::string_view> pubkey_hex;
        if (pubkey_hex_)
            pubkey_hex.emplace(pubkey_hex_, 66);

        std::vector<config_message> confs;
        confs.reserve(count);

        for (size_t i = 0; i < count; i++)
            confs.emplace_back(
                    static_cast<config::Namespace>(configs[i].namespace_),
                    configs[i].hash,
                    configs[i].timestamp_ms,
                    ustring{configs[i].data, configs[i].datalen});

        auto result = unbox(state).merge(pubkey_hex, confs);
        unbox(state).log(LogLevel::info, "Merged " + std::to_string(result.size()));
        *successful_hashes = make_string_list(result);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API bool state_current_hashes(
        state_object* state, const char* pubkey_hex_, session_string_list** current_hashes) {
    try {
        std::optional<std::string_view> pubkey_hex;
        if (pubkey_hex_)
            pubkey_hex.emplace(pubkey_hex_, 66);

        auto result = unbox(state).current_hashes(pubkey_hex);
        *current_hashes = make_string_list(result);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API seqno_t
state_current_seqno(state_object* state, const char* pubkey_hex_, NAMESPACE namespace_) {
    switch (namespace_) {
        case NAMESPACE_CONTACTS: return unbox(state).config<Contacts>().get_seqno();
        case NAMESPACE_CONVO_INFO_VOLATILE:
            return unbox(state).config<ConvoInfoVolatile>().get_seqno();
        case NAMESPACE_USER_GROUPS: return unbox(state).config<UserGroups>().get_seqno();
        case NAMESPACE_USER_PROFILE: return unbox(state).config<UserProfile>().get_seqno();
        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex_
    if (!pubkey_hex_)
        return -1;

    try {
        std::string_view pubkey_hex = {pubkey_hex_, 66};

        switch (namespace_) {
            case NAMESPACE_GROUP_INFO:
                return unbox(state).config<groups::Info>({pubkey_hex_, 66}).get_seqno();
            case NAMESPACE_GROUP_MEMBERS:
                return unbox(state).config<groups::Members>({pubkey_hex_, 66}).get_seqno();
            case NAMESPACE_GROUP_KEYS: return 0;  // No seqno needed for GROUP_KEYS
            default: return -1;
        }
    } catch (...) {
        return -1;
    }
}

LIBSESSION_C_API bool state_dump(
        state_object* state, bool full_dump, unsigned char** out, size_t* outlen) {
    try {
        assert(out && outlen);
        auto data = unbox(state).dump(full_dump);
        *outlen = data.size();
        *out = static_cast<unsigned char*>(std::malloc(data.size()));
        std::memcpy(*out, data.data(), data.size());
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API bool state_dump_namespace(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex_,
        unsigned char** out,
        size_t* outlen) {
    assert(out && outlen);

    try {
        std::optional<std::string_view> pubkey_hex;
        if (pubkey_hex_)
            pubkey_hex.emplace(pubkey_hex_, 66);

        auto target_namespace = static_cast<Namespace>(namespace_);
        auto data = unbox(state).dump(target_namespace, pubkey_hex);
        *outlen = data.size();
        *out = static_cast<unsigned char*>(std::malloc(data.size()));
        std::memcpy(*out, data.data(), data.size());
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API bool state_get_keys(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex_,
        unsigned char** out,
        size_t* outlen) {
    try {
        std::optional<std::string_view> pubkey_hex;
        if (pubkey_hex_)
            pubkey_hex.emplace(pubkey_hex_, 66);

        auto target_namespace = static_cast<Namespace>(namespace_);
        auto data = unbox(state).get_keys(target_namespace, pubkey_hex);
        *outlen = data.size();
        *out = static_cast<unsigned char*>(std::malloc(data.size()));
        std::memcpy(*out, data.data(), data.size());
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API void state_create_group(
        state_object* state,
        const char* name,
        size_t name_len,
        const char* description_,
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
        void* ctx) {
    assert(name);
    try {
        std::optional<std::string_view> description;
        if (description_)
            description = {description_, description_len};

        std::string_view url{pic_.url};
        ustring_view key;
        if (!url.empty())
            key = {pic_.key, 32};

        std::optional<profile_pic> pic = profile_pic{url, key};
        std::vector<groups::member> members = {};
        members.reserve(members_len);

        for (size_t i = 0; i < members_len; i++) {
            members.emplace_back(groups::member{members_[i]});
        }

        unbox(state).create_group(
                {name, name_len},
                description,
                pic,
                members,
                [callback, ctx](
                        std::string_view group_id,
                        ustring_view group_sk,
                        std::optional<std::string_view> error) {
                    callback(group_id.data(), group_sk.data(), error->data(), error->size(), ctx);
                });
    } catch (const std::exception& e) {
        std::string_view err = e.what();
        set_error(state, err);
        callback(nullptr, nullptr, e.what(), err.size(), ctx);
    }
}

LIBSESSION_C_API void state_approve_group(
        state_object* state, const char* group_id, unsigned const char* group_sk) {
    try {
        std::optional<ustring_view> ed_sk;
        if (group_sk)
            ed_sk = {group_sk, 64};

        unbox(state).approve_group({group_id, 66}, ed_sk);
    } catch (...) {
    }
}

LIBSESSION_C_API bool state_load_group_admin_key(
        state_object* state, const char* group_id, unsigned const char* seed) {
    try {
        std::string gid = {group_id, 66};
        unbox(state).load_group_admin_key({group_id, 66}, ustring_view{seed, 32});
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API void state_erase_group(
        state_object* state, const char* group_id, bool remove_user_record) {
    try {
        unbox(state).erase_group({group_id, 66}, remove_user_record);
    } catch (...) {
    }
}

LIBSESSION_C_API bool state_mutate_user(
        state_object* state, void (*callback)(mutable_user_state_object*, void*), void* ctx) {
    try {
        auto s_object = new mutable_user_state_object();
        auto mutable_state = unbox(state).mutable_config([state](std::string_view e) {
            // Don't override an existing error
            if (state->last_error)
                return;

            set_error(state, e);
        });
        s_object->internals = &mutable_state;
        callback(s_object, ctx);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API bool state_mutate_group(
        state_object* state,
        const char* pubkey_hex,
        void (*callback)(mutable_group_state_object*, void*),
        void* ctx) {
    try {
        auto s_object = new mutable_group_state_object();
        auto mutable_state =
                unbox(state).mutable_config({pubkey_hex, 66}, [state](std::string_view e) {
                    // Don't override an existing error
                    if (state->last_error)
                        return;

                    set_error(state, e);
                });
        s_object->internals = &mutable_state;
        callback(s_object, ctx);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API void mutable_user_state_set_error_if_empty(
        mutable_user_state_object* state, const char* err, size_t err_len) {
    if (auto set_error = unbox(state).set_error; set_error.has_value())
        set_error.value()({err, err_len});
}

LIBSESSION_C_API void mutable_group_state_set_error_if_empty(
        mutable_group_state_object* state, const char* err, size_t err_len) {
    if (auto set_error = unbox(state).set_error; set_error.has_value())
        set_error.value()({err, err_len});
}

}  // extern "C"
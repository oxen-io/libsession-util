#include "session/protos.hpp"

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"

namespace session::protos {

SessionProtos::SharedConfigMessage_Kind encode_namespace(session::config::Namespace t) {
    switch (t) {
        case session::config::Namespace::UserProfile:
            return SessionProtos::SharedConfigMessage_Kind_USER_PROFILE;
        case session::config::Namespace::Contacts:
            return SessionProtos::SharedConfigMessage_Kind_CONTACTS;
        case session::config::Namespace::ConvoInfoVolatile:
            return SessionProtos::SharedConfigMessage_Kind_CONVO_INFO_VOLATILE;
        case session::config::Namespace::UserGroups:
            return SessionProtos::SharedConfigMessage_Kind_USER_GROUPS;
        default:
            throw std::invalid_argument{"Error: cannot encode invalid SharedConfigMessage type"};
    }
}

ustring parse_request(const WebSocketProtos::WebSocketRequestMessage& msg) {
    const auto& data = msg.body();
    auto envelope = SessionProtos::Envelope();

    if (auto b = envelope.ParseFromString(
                {reinterpret_cast<const char*>(data.data()), data.size()})) {
        const auto& content = envelope.content();
        auto config = SessionProtos::SharedConfigMessage();

        if (auto c = config.ParseFromString(content)) {
            const auto& kind = config.kind();
            const auto& s = config.data();

            switch (kind) {
                case (SessionProtos::SharedConfigMessage_Kind_USER_PROFILE):
                case (SessionProtos::SharedConfigMessage_Kind_CONTACTS):
                case (SessionProtos::SharedConfigMessage_Kind_CONVO_INFO_VOLATILE):
                case (SessionProtos::SharedConfigMessage_Kind_USER_GROUPS):
                    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
                default: throw std::invalid_argument{"Error: received invalid SharedConfigMessage"};
            }
        }
    }

    throw std::invalid_argument{"Error: received invalid WebSocketRequestMessage"};
}

ustring handle_incoming(ustring_view data) {
    auto req = WebSocketProtos::WebSocketMessage();

    if (auto b = req.ParseFromString({reinterpret_cast<const char*>(data.data()), data.size()})) {
        const auto& msg_type = req.type();

        switch (msg_type) {
            case (WebSocketProtos::WebSocketMessage_Type_REQUEST):
                return parse_request(req.request());
            case (WebSocketProtos::WebSocketMessage_Type_UNKNOWN):
            case (WebSocketProtos::WebSocketMessage_Type_RESPONSE):
                throw std::invalid_argument{"Error: received invalid WebSocketRequest"};
        }
    }

    // if ParseFromString fails, we have a raw (not protobuf encoded) message
    return {data.data(), data.size()};
}

ustring handle_incoming(ustring data) {
    return handle_incoming(ustring_view{data.data(), data.size()});
}

ustring handle_outgoing(ustring_view data, int64_t seqno, config::Namespace t) {
    if (static_cast<int16_t>(t) > 5)
        throw std::invalid_argument{"Error: received invalid outgoing SharedConfigMessage type"};

    auto config = SessionProtos::SharedConfigMessage();
    config.set_kind(encode_namespace(t));
    config.set_seqno(seqno);
    *config.mutable_data() = std::string{reinterpret_cast<const char*>(data.data()), data.size()};

    auto envelope = SessionProtos::Envelope();
    *envelope.mutable_content() = config.SerializeAsString();
    envelope.set_timestamp(0);
    envelope.set_type(SessionProtos::Envelope_Type::Envelope_Type_SESSION_MESSAGE);

    auto webreq = WebSocketProtos::WebSocketRequestMessage();
    webreq.set_verb("");
    webreq.set_path("");
    webreq.set_requestid(0);
    *webreq.mutable_body() = envelope.SerializeAsString();

    auto msg = WebSocketProtos::WebSocketMessage();
    msg.set_type(WebSocketProtos::WebSocketMessage_Type_REQUEST);
    *msg.mutable_request() = webreq;

    std::string output = msg.SerializeAsString();
    return {reinterpret_cast<const unsigned char*>(output.data()), output.size()};
}

ustring handle_outgoing(ustring data, int64_t seqno, config::Namespace t) {
    return handle_outgoing(ustring_view{data.data(), data.size()}, seqno, t);
}

}  // namespace session::protos

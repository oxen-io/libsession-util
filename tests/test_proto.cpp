#include <catch2/catch_all.hpp>
#include <iostream>
#include <session/protos.hpp>

#include "utils.hpp"

using namespace session;

const std::vector<config::Namespace> groups{
        config::Namespace::UserProfile,
        config::Namespace::Contacts,
        config::Namespace::ConvoInfoVolatile,
        config::Namespace::UserGroups};

TEST_CASE("Protobuf Handling - Wrap, Unwrap", "[config][proto][wrap]") {
    auto msg = "Hello from the other side"_bytes;

    SECTION("Wrap/unwrap message types") {
        for (auto& n : groups) {
            auto shared_config_msg = protos::handle_outgoing(msg, 1, n);

            CHECK(not shared_config_msg.empty());

            auto shared_config_parsed = protos::handle_incoming(shared_config_msg);
            // This will be false, as ::handle_incoming will return the parsed payload if it
            // successfully parses a protobuf wrapped message
            CHECK_FALSE(shared_config_msg == shared_config_parsed);
            // This will return true, as the parsed message will match the payload
            CHECK(shared_config_parsed == msg);
        }
    }

    SECTION("Message type payload comparison") {
        auto user_profile_msg = protos::handle_outgoing(msg, 1, config::Namespace::UserProfile);
        auto contacts_msg = protos::handle_outgoing(msg, 1, config::Namespace::Contacts);

        auto user_profile_parsed = protos::handle_incoming(user_profile_msg);
        auto contacts_parsed = protos::handle_incoming(contacts_msg);

        // All of these will return true, as the parsed messages will be identical to the
        // payload, and therefore identical to one another
        CHECK(user_profile_parsed == contacts_parsed);
        CHECK(user_profile_parsed == msg);
        CHECK(contacts_parsed == msg);
    }
}

TEST_CASE("Protobuf Handling - Error Handling", "[config][proto][error]") {
    auto msg = "Hello from the other side"_bytes;
    auto addendum = "jfeejj0ifdoesam"_bytes;

    const auto user_profile_msg = protos::handle_outgoing(msg, 1, config::Namespace::UserProfile);
    const auto size = user_profile_msg.size();

    // Testing three positions: front, inside the payload, and at the end
    const std::vector<size_t> positions{0, size - 4, size};

    for (auto& p : positions) {
        auto msg_copy = user_profile_msg;
        msg_copy.insert(p, addendum);

        auto msg_parsed = protos::handle_incoming(msg_copy);
        // This will be true, as ::handle_incoming will return the same input string if it
        // fails to parse it as a protobuf wrapped message
        CHECK(msg_copy == msg_parsed);
        // This will be false, as the wrapped message will not match the payload
        CHECK_FALSE(msg_parsed == msg);
    }
}

#pragma once
#include <memory>
#include <optional>
#include <session/config.hpp>
#include <session/types.hpp>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>

namespace session::config {

/// Base class for types representing a community; this base type handles the url/room/pubkey that
/// such a type need.  Generally a class inherits from this to extend with the local
/// community-related values.
struct community {

    // 267 = len('https://') + 253 (max valid DNS name length) + len(':XXXXX')
    static constexpr size_t BASE_URL_MAX_LENGTH = 267;
    static constexpr size_t ROOM_MAX_LENGTH = 64;

    community() = default;

    // Constructs an empty community struct from url, room, and pubkey.  `base_url` will be
    // normalized if not already.  pubkey is 32 bytes.
    community(std::string_view base_url, std::string_view room, ustring_view pubkey);

    // Same as above, but takes pubkey as an encoded (hex or base32z or base64) string.
    community(std::string_view base_url, std::string_view room, std::string_view pubkey_encoded);

    // Takes a combined room URL (e.g. https://whatever.com/r/Room?public_key=01234....), either
    // new style (with /r/) or old style (without /r/).  Note that the URL gets canonicalized so
    // the resulting `base_url()` and `room()` values may not be exactly equal to what is given.
    //
    // See also `parse_full_url` which does the same thing but returns it in pieces rather than
    // constructing a new `community` object.
    explicit community(std::string_view full_url);

    /// API: community/community::set_full_url
    ///
    /// Replaces the baseurl/room/pubkey of this object from a URL.  This parses the URL, then stores
    /// the values as if passed to set_base_url/set_room/set_pubkey.
    ///
    /// The base URL will be normalized; the room name will be case-preserving (but see `set_room`
    /// for info on limitations on "case-preserving", particularly for volatile configs); and the
    /// embedded pubkey must be encoded in one of hex, base32z, or base64.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_full_url(std::string_view full_url);
    /// ```
    ///
    /// Inputs:
    /// - `full_url` -- URL to be stored
    ///
    /// Outputs:
    /// - `void` -- Nothing returned
    void set_full_url(std::string_view full_url);

    /// API: community/community::set_base_url
    ///
    /// Replaces the base_url of this object.  Note that changing the URL and then giving it to `set`
    /// will end up inserting a *new* record but not removing the *old* one (you need to erase first
    /// to do that).
    ///
    /// Declaration:
    /// ```cpp
    /// void set_base_url(std::string_view new_url);
    /// ```
    ///
    /// Inputs:
    /// - `new_url` -- URL to be stored
    ///
    /// Outputs:
    /// - `void` -- Nothing returned
    void set_base_url(std::string_view new_url);

    /// API: community/community::set_room
    ///
    /// Changes the room token.  This stores (or updates) the name as given as the localized room,
    /// and separately stores the normalized (lower-case) token.  Note that the localized name does
    /// not persist across a push or dump in some config contexts (such as volatile room info).  If
    /// the new room given here changes more than just case (i.e. if the normalized room token
    /// changes) then a call to `set` will end up inserting a *new* record but not removing the *old*
    /// one (you need to erase first to do that).
    ///
    /// Declaration:
    /// ```cpp
    /// void set_room(std::string_view room);
    /// ```
    ///
    /// Inputs:
    /// - `room` -- Room to be stored
    ///
    /// Outputs:
    /// - `void` -- Nothing returned
    void set_room(std::string_view room);

    /// API: community/community::set_pubkey
    ///
    /// Updates the pubkey of this community (typically this is not called directly but rather
    /// via `set_server` or during construction).  Throws std::invalid_argument if the given
    /// pubkey does not look like a valid pubkey.  The std::string_view version takes the pubkey
    /// as any of hex/base64/base32z.
    ///
    /// NOTE: the pubkey of all communities with the same URLs are stored in common, so changing
    /// one community pubkey (and storing) will affect all communities using the same community
    /// base URL.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_pubkey(ustring_view pubkey);
    /// void set_pubkey(std::string_view pubkey);
    /// ```
    ///
    /// Inputs:
    /// - `pubkey` -- Pubkey to be stored
    ///
    /// Outputs:
    /// - `void` -- Nothing returned
    void set_pubkey(ustring_view pubkey);
    void set_pubkey(std::string_view pubkey);

    /// API: community/community::base_url
    ///
    /// Accesses the base url (i.e. not including room or pubkey). Always lower-case/normalized.
    ///
    /// Declaration:
    /// ```cpp
    /// const std::string& base_url() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string&` -- Returns the base url
    const std::string& base_url() const { return base_url_; }

    /// API: community/community::room
    ///
    /// Accesses the room token; this is case-preserving, where possible.  In some contexts, however,
    /// such as volatile info, the case is not preserved and this will always return the normalized
    /// (lower-case) form rather than the preferred form.
    ///
    /// Declaration:
    /// ```cpp
    /// const std::string& room() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string&` -- Returns the room token
    const std::string& room() const { return localized_room_ ? *localized_room_ : room_; }

    /// API: community/community::room
    ///
    /// Accesses the normalized room token, i.e. always lower-case.
    ///
    /// Declaration:
    /// ```cpp
    /// const std::string& room_norm() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string&` -- Returns the room token
    const std::string& room_norm() const { return room_; }

    /// API: community/community::pubkey
    ///
    /// Accesses the server pubkey (32 bytes).
    ///
    /// Declaration:
    /// ```cpp
    /// const ustring& pubkey() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `ustring&` -- Returns the pubkey
    const ustring& pubkey() const { return pubkey_; }

    /// API: community/community::pubkey_hex
    ///
    /// Accesses the server pubkey as hex (64 hex digits).
    ///
    /// Declaration:
    /// ```cpp
    /// std::string pubkey_hex() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string` -- Returns the pubkey
    std::string pubkey_hex() const;

    /// API: community/community::pubkey_b32z
    ///
    /// Accesses the server pubkey as base32z (52 alphanumeric digits)
    ///
    /// Declaration:
    /// ```cpp
    /// std::string pubkey_b32z() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string` -- Returns the pubkey
    std::string pubkey_b32z() const;

    /// API: community/community::pubkey_b64
    ///
    /// Accesses the server pubkey as unpadded base64 (43 from alphanumeric, '+', and '/').
    ///
    /// Declaration:
    /// ```cpp
    /// std::string pubkey_b64() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string` -- Returns the pubkey
    std::string pubkey_b64() const;

    /// API: community/community::full_url
    ///
    /// Constructs and returns the full URL for this room.  See below.
    ///
    /// Declaration:
    /// ```cpp
    /// std::string full_url() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::string` -- Returns the Full URL
    std::string full_url() const;

    /// API: community/community::full_url(std::string_view,std::string_view,ustring_view)
    ///
    /// Constructs and returns the full URL for a given base, room, and pubkey.  Currently this
    /// returns it in a Session-compatibility form (https://server.com/RoomName?public_key=....), but
    /// future versions are expected to change to use (https://server.com/r/RoomName?public_key=...),
    /// which this library also accepts.
    ///
    /// Declaration:
    /// ```cpp
    /// static std::string full_url(
    ///        std::string_view base_url, std::string_view room, ustring_view pubkey);
    /// ```
    ///
    /// Inputs:
    /// - `base_url` -- string of the base url to construct the full url with
    /// - `room` -- string of the room token to construct the full url with
    /// - `pubkey` -- binary of the pubkey to construct the full url with
    ///
    /// Outputs:
    /// - `std::string` -- Returns the Full URL
    static std::string full_url(
            std::string_view base_url, std::string_view room, ustring_view pubkey);

    /// API: community/community::canonical_url
    ///
    /// Takes a base URL as input and returns it in canonical form.  This involves doing things
    /// like lower casing it and removing redundant ports (e.g. :80 when using http://).  Throws
    /// std::invalid_argument if given an invalid base URL.
    ///
    /// Declaration:
    /// ```cpp
    /// static std::string canonical_url(std::string_view url);
    /// ```
    ///
    /// Inputs:
    /// - `url` -- string of the url to construct the canonical url with
    ///
    /// Outputs:
    /// - `std::string` -- Returns the canonical URL
    static std::string canonical_url(std::string_view url);

    /// API: community/community::canonical_room
    ///
    /// Takes a room token and returns it in canonical form (i.e. lower-cased).  Throws
    /// std::invalid_argument if given an invalid room token (e.g. too long, or containing token
    /// other than a-z, 0-9, -, _).
    ///
    /// Declaration:
    /// ```cpp
    /// static std::string canonical_room(std::string_view room);
    /// ```
    ///
    /// Inputs:
    /// - `room` -- string of the room token to construct the canonical room with
    ///
    /// Outputs:
    /// - `std::string` -- Returns the canonical room
    static std::string canonical_room(std::string_view room);

    /// API: community/community::canonicalize_url
    ///
    /// Same as above canonical_url, but modifies the argument in-place instead of returning a modified
    /// copy.
    ///
    /// Declaration:
    /// ```cpp
    /// static void canonicalize_url(std::string& url);
    /// ```
    ///
    /// Inputs:
    /// - `url` -- string of the url to modify to the canonical url
    ///
    /// Outputs:
    /// - `void` -- Returns Nothing
    static void canonicalize_url(std::string& url);

    /// API: community/community::canonicalize_room
    ///
    /// Same as above canonical_room, but modifies the argument in-place instead of returning a modified
    /// copy.
    ///
    /// Declaration:
    /// ```cpp
    /// static void canonicalize_room(std::string& room);
    /// ```
    ///
    /// Inputs:
    /// - `room` -- string of the room to modify to the canonical room
    ///
    /// Outputs:
    /// - `void` -- Returns Nothing
    static void canonicalize_room(std::string& room);

    /// API: community/community::parse_full_url
    ///
    /// Takes a full room URL, splits it up into canonical url (see above), room, and server
    /// pubkey.  We take both the deprecated form (e.g.
    /// https://example.com/SomeRoom?public_key=...) and new form
    /// (https://example.com/r/SomeRoom?public_key=...).  The public_key is typically specified
    /// in hex (64 digits), but we also accept base64 (43 chars or 44 with padding) and base32z
    /// (52 chars) encodings (for slightly shorter URLs).
    ///
    /// The returned URL is normalized (lower-cased, and cleaned up).
    ///
    /// The returned room name is *not* normalized, that is, it preserve case.
    ///
    /// Throw std::invalid_argument if anything in the URL is unparseable or invalid.
    ///
    /// Declaration:
    /// ```cpp
    /// static std::tuple<std::string, std::string, ustring> parse_full_url(std::string_view full_url);
    /// ```
    ///
    /// Inputs:
    /// - `full_url` -- string of the url to parse
    ///
    /// Outputs:
    /// - `std::tuple` -- Tuple of 3 components of the url
    ///     - `std::string` -- canonical url, normalized
    ///     - `std::string` -- room name, *not* normalized
    ///     - `ustring` -- binary of the server pubkey
    static std::tuple<std::string, std::string, ustring> parse_full_url(std::string_view full_url);

    /// API: community/community::parse_partial_url
    ///
    /// Takes a full or partial room URL (partial here meaning missing the ?public_key=...) and
    /// splits it up into canonical url, room, and (if present) pubkey.
    ///
    /// Declaration:
    /// ```cpp
    /// static std::tuple<std::string, std::string, std::optional<ustring>> parse_partial_url(std::string_view url);
    /// ```
    ///
    /// Inputs:
    /// - `url` -- string of the url to parse
    ///
    /// Outputs:
    /// - `std::tuple` -- Tuple of 3 components of the url
    ///     - `std::string` -- canonical url, normalized
    ///     - `std::string` -- room name, *not* normalized
    ///     - `std::optional<ustring>` -- optional binary of the server pubkey if present
    static std::tuple<std::string, std::string, std::optional<ustring>> parse_partial_url(
            std::string_view url);

  protected:
    // The canonical base url and room (i.e. lower-cased, URL cleaned up):
    std::string base_url_, room_;
    // The localized token of this room, that is, with case preserved (so `room_` could be
    // `someroom` and this could `SomeRoom`).  Omitted if not available.
    std::optional<std::string> localized_room_;
    // server pubkey
    ustring pubkey_;

    // Construction without a pubkey for when pubkey isn't known yet but will be set shortly
    // after constructing (or when isn't needed, such as when deleting).
    community(std::string_view base_url, std::string_view room);
};

struct comm_iterator_helper {

    comm_iterator_helper(dict::const_iterator it_server, dict::const_iterator end_server) :
            it_server{std::move(it_server)}, end_server{std::move(end_server)} {}

    std::optional<dict::const_iterator> it_server, end_server, it_room, end_room;

    bool operator==(const comm_iterator_helper& other) const {
        return it_server == other.it_server && it_room == other.it_room;
    }

    void next_server() {
        ++*it_server;
        it_room.reset();
        end_room.reset();
    }

    bool done() const { return !it_server || *it_server == *end_server; }

    template <typename Comm, typename Any>
    bool load(std::shared_ptr<Any>& val) {
        while (it_server) {
            if (*it_server == *end_server) {
                it_server.reset();
                end_server.reset();
                return false;
            }

            auto& [base_url, server_info] = **it_server;
            auto* server_info_dict = std::get_if<dict>(&server_info);
            if (!server_info_dict) {
                next_server();
                continue;
            }

            const std::string* pubkey_raw = nullptr;
            if (auto pubkey_it = server_info_dict->find("#"); pubkey_it != server_info_dict->end())
                if (auto* pk_sc = std::get_if<scalar>(&pubkey_it->second))
                    pubkey_raw = std::get_if<std::string>(pk_sc);

            if (!pubkey_raw) {
                next_server();
                continue;
            }

            ustring_view pubkey{
                    reinterpret_cast<const unsigned char*>(pubkey_raw->data()), pubkey_raw->size()};

            if (!it_room) {
                if (auto rit = server_info_dict->find("R");
                    rit != server_info_dict->end() && std::holds_alternative<dict>(rit->second)) {
                    auto& rooms_dict = std::get<dict>(rit->second);
                    it_room = rooms_dict.begin();
                    end_room = rooms_dict.end();
                } else {
                    next_server();
                    continue;
                }
            }

            while (it_room) {
                if (*it_room == *end_room) {
                    it_room.reset();
                    end_room.reset();
                    break;
                }

                auto& [room, data] = **it_room;
                auto* data_dict = std::get_if<dict>(&data);
                if (!data_dict) {
                    ++*it_room;
                    continue;
                }

                val = std::make_shared<Any>(Comm{});
                auto& og = std::get<Comm>(*val);
                try {
                    og.set_base_url(base_url);
                    og.set_room(room);  // Will be replaced with "n" in the `.load` below
                    og.set_pubkey(pubkey);
                    og.load(*data_dict);
                } catch (const std::exception& e) {
                    ++*it_room;
                    continue;
                }
                return true;
            }

            ++*it_server;
        }

        return false;
    }

    bool advance() {
        if (it_room) {
            ++*it_room;
            return true;
        }
        if (it_server) {
            ++*it_server;
            return true;
        }
        return false;
    }
};

}  // namespace session::config

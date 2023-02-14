#include "session/config/profile_pic.hpp"

#include <stdexcept>

namespace session::config {

void profile_pic::set_url(std::string new_url) {
    url = (url_ = std::move(new_url));
}

void profile_pic::set_key(ustring new_key) {
    if (new_key.size() != 32)
        throw std::invalid_argument{"Invalid profile pic key: not 32 bytes"};

    key = (key_ = std::move(new_key));
}

}  // namespace session::config

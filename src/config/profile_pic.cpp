#include "session/config/profile_pic.hpp"

namespace session::config {

void profile_pic::set_url(std::string new_url) {
    url = (url_ = std::move(new_url));
}

void profile_pic::set_key(ustring new_key) {
    key = (key_ = std::move(new_key));
}

}  // namespace session::config

#include "session/config.hpp"

#include "session/bt_merge.hpp"

#include <oxenc/bt_serialize.h>

namespace session {

oxenc::bt_dict config_base::final_dict() const {
    return bt::merge(known_dict(), unknown);
}

std::string config_base::serialize() const {
    return oxenc::bt_serialize(final_dict());
}

}  // namespace session

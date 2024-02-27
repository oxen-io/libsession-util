#pragma once

#include <string>

namespace session {

struct Error {
    static constexpr const char* READ_ONLY_CONFIG = "Unable to make changes to a read-only config object";
};

}  // namespace session

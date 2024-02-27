#include "session/errors.hpp"

#include "session/export.h"

namespace session {

LIBSESSION_C_API const char* SESSION_ERROR_READ_ONLY_CONFIG = Error::READ_ONLY_CONFIG;

}  // extern "C"

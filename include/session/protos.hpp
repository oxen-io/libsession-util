#pragma once

#include "session/config/namespaces.hpp"
#include "session/util.hpp"

namespace session::protos {

ustring handle_incoming(ustring_view data);

ustring handle_outgoing(ustring_view data, int64_t seqno, config::Namespace t);

}  // namespace session::protos

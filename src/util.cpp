#include <sodium/utils.h>

#include <session/util.hpp>

namespace session {
void* sodium_buffer_allocate(size_t length) {
    if (auto* p = sodium_malloc(length))
        return p;
    throw std::bad_alloc{};
}

void sodium_buffer_deallocate(void* p) {
    if (p)
        sodium_free(p);
}
}  // namespace session

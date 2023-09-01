
function(check_target target)
    if (NOT TARGET ${target})
        message(FATAL_ERROR "Project failed to compile required target: ${target}")
    endif()
endfunction()

include(FetchContent)

FetchContent_Declare(
    protobuf
    GIT_REPOSITORY  https://github.com/protocolbuffers/protobuf.git
    GIT_TAG         v3.21.12     # apparently this must be a tag (not hash) for git_shallow to work?
    GIT_SHALLOW     TRUE
    GIT_PROGRESS    TRUE
)

set(protobuf_VERBOSE ON CACHE BOOL "" FORCE)
set(protobuf_INSTALL ON CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBPROTOC OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_ABSL_PROVIDER "module" CACHE STRING "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES OFF CACHE BOOL "")
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)

message(STATUS "Pulling protobuf repository...")

FetchContent_MakeAvailable(protobuf)

check_target(protobuf::libprotobuf-lite)

libsession_static_bundle(protobuf::libprotobuf-lite)


add_custom_target(regen-protobuf
    protoc --cpp_out=. SessionProtos.proto WebSocketResources.proto
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

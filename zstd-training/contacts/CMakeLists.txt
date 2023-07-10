
find_package(pybind11 REQUIRED)

add_executable(gen-training gen-training.cpp)

target_link_libraries(gen-training PRIVATE config pybind11::embed fmt)


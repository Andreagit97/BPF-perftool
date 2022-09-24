#
# yaml-cpp
#
set(YAMLCPP_SRC "${PROJECT_BINARY_DIR}/yamlcpp-prefix/src/yamlcpp")
set(YAMLCPP_LIB "${YAMLCPP_SRC}/libyaml-cpp.a")
set(YAMLCPP_INCLUDE_DIR "${YAMLCPP_SRC}/include")
ExternalProject_Add(
    yamlcpp
    URL "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.6.2.tar.gz"
    URL_HASH "SHA256=e4d8560e163c3d875fd5d9e5542b5fd5bec810febdcba61481fe5fc4e6b1fd05"
    BUILD_BYPRODUCTS ${YAMLCPP_LIB}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")

include_directories(${YAMLCPP_INCLUDE_DIR})

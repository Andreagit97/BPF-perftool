

set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
set(ZLIB_INCLUDE "${ZLIB_SRC}")
set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
ExternalProject_Add(zlib
    PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
    URL "https://github.com/madler/zlib/archive/v1.2.11.tar.gz"
    URL_HASH "SHA256=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff"
    CONFIGURE_COMMAND ./configure --prefix=${ZLIB_SRC}
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    BUILD_BYPRODUCTS ${ZLIB_LIB}
    INSTALL_COMMAND "")

include_directories(${ZLIB_INCLUDE})

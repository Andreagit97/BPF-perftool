#
# libbpf
#
set(LIBBPF_SRC "${PROJECT_BINARY_DIR}/libbpf-prefix/src")
set(LIBBPF_BUILD_DIR "${LIBBPF_SRC}/libbpf-build")
set(LIBBPF_INCLUDE "${LIBBPF_BUILD_DIR}/root/usr/include")
set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/root/usr/lib64/libbpf.a")
ExternalProject_Add(
    libbpf
    PREFIX "${PROJECT_BINARY_DIR}/libbpf-prefix"
    DEPENDS zlib
    URL "https://github.com/libbpf/libbpf/archive/refs/tags/v0.8.0.tar.gz"
    URL_HASH
    "SHA256=f4480242651a93c101ece320030f6b2b9b437f622f807719c13cb32569a6d65a"
    CONFIGURE_COMMAND mkdir -p build root
    BUILD_COMMAND BUILD_STATIC_ONLY=y OBJDIR=${LIBBPF_BUILD_DIR}/build DESTDIR=${LIBBPF_BUILD_DIR}/root make -C ${LIBBPF_SRC}/libbpf/src install
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
)

include_directories(${LIBBPF_INCLUDE})

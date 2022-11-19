#
# libaudit, we only search it in the system
#
find_path(LIBAUDIT_INCLUDE libaudit.h)
find_library(LIBAUDIT_LIB NAMES audit)

if(LIBAUDIT_INCLUDE AND LIBAUDIT_LIB)
    message(STATUS "Found libaudit: include: ${LIBAUDIT_INCLUDE}, lib: ${LIBAUDIT_LIB}")
else()
    message(FATAL_ERROR "Couldn't find system libaudit")
endif()

include_directories(${LIBAUDIT_INCLUDE})

#
# jsoncpp, we only search it in the system
#
find_path(JSONCPP_INCLUDE json/json.h PATH_SUFFIXES jsoncpp)
find_library(JSONCPP_LIB NAMES jsoncpp)

if(JSONCPP_INCLUDE AND JSONCPP_LIB)
    message(STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
else()
    message(FATAL_ERROR "Couldn't find system jsoncpp")
endif()

include_directories(${JSONCPP_INCLUDE})

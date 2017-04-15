# Try to find PolarSSL/mbedtls library
#
# Returns
# POLARSSL_FOUND
# POLARSSL_INCLUDE_DIRS
# POLARSSL_LIBRARIES
# POLARSSL_VERSION_MAJOR
# POLARSSL_VERSION_MINOR
# POLARSSL_VERSION_PATCH
# POLARSSL_VERSION_STRING
# POLARSSL_INC_FOLDER
# POLARSSL_REAL_NAME

include(FindPackageHandleStandardArgs)

find_path(POLARSSL_INCLUDE_DIRS NAMES mbedtls/ssl.h HINTS /usr/local/include)
set(POLARSSL_REAL_NAME MBEDTLS)
if( "${POLARSSL_INCLUDE_DIRS}" STREQUAL "POLARSSL_INCLUDE_DIRS-NOTFOUND")
  find_path(POLARSSL_INCLUDE_DIRS NAMES polarssl/ssl.h)
  set(POLARSSL_REAL_NAME POLARSSL)
endif()

string(TOLOWER "${POLARSSL_REAL_NAME}" POLARSSL_INC_FOLDER)

#
# polarssl -> mbedtls
# Try to find first libmbedcrypto.a, then libmbedtls.a, and if this fails tries
# to find polarssl.
# Only because mbed is separating ssl/tls functions from crypto (aes/sha)
# functions and some distrib (like osx or fedora) do not symbolically link
# libmbedtls to polarssl for compat
#
find_library(POLARSSL_LIBRARIES NAMES mbedcrypto)
set(POLARSSL_USED_LIBRARY mbedcrypto)
if( "${POLARSSL_LIBRARIES}" STREQUAL "POLARSSL_LIBRARIES-NOTFOUND" )
  find_library(POLARSSL_LIBRARIES NAMES mbedtls)
  set(POLARSSL_USED_LIBRARY mbedtls)
  if( "${POLARSSL_LIBRARIES}" STREQUAL "POLARSSL_LIBRARIES-NOTFOUND" )
    find_library(POLARSSL_LIBRARIES NAMES polarssl)
    set(POLARSSL_USED_LIBRARY polarssl)
  endif()
endif()

find_package_handle_standard_args(POLARSSL REQUIRED_VARS POLARSSL_INCLUDE_DIRS POLARSSL_LIBRARIES)

if( ${POLARSSL_LIBRARIES-NOTFOUND} )
  message(FATAL_ERROR "Failed to get info from PolarSSL library, check your PolarSSL installation")
  set(POLARSSL_FOUND False)
  return()
endif()

if( NOT CMAKE_CROSSCOMPILING )
  execute_process(
    COMMAND echo "#include <${POLARSSL_INC_FOLDER}/version.h>\n#include <stdio.h>\nint main(){printf(${POLARSSL_REAL_NAME}_VERSION_STRING);return 0;}"
    OUTPUT_FILE a.c
  )
  execute_process(
    COMMAND ${CMAKE_C_COMPILER} a.c -I${POLARSSL_INCLUDE_DIRS} ${POLARSSL_LIBRARIES}
  )
  execute_process(
    COMMAND ./a.out
    OUTPUT_VARIABLE POLARSSL_VERSION_STRING
  )
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E remove a.c a.out
  )
else()
  execute_process(
    COMMAND grep -w "MBEDTLS_VERSION_STRING" ${POLARSSL_INCLUDE_DIRS}/${POLARSSL_INC_FOLDER}/version.h
    COMMAND sed -e "s@\s\+@ @g"
    COMMAND cut -d\  -f3
    COMMAND sed -e "s@\"@@g"
    OUTPUT_VARIABLE POLARSSL_VERSION_STRING
  )
endif()

message("PolarSSL/mbedTLS version: " ${POLARSSL_VERSION_STRING})

if( "${POLARSSL_VERSION_STRING}" STREQUAL "2.0.0" AND NOT "${POLARSSL_USED_LIBRARY}" STREQUAL "mbedcrypto" )
  message("*** WARNING *** Your mbedTLS version is 2.0.0, it's possible the `make' command doesn't work.\nPlease refer to the INSTALL.md's \"mbedTLS 2.0.0\" section if you have any problem.\n")
endif()

string(REPLACE "." ";" POLARSSL_VERSION_LIST ${POLARSSL_VERSION_STRING})

list(GET ${POLARSSL_VERSION_LIST} 0 POLARSSL_VERSION_MAJOR)
list(GET ${POLARSSL_VERSION_LIST} 1 POLARSSL_VERSION_MINOR)
list(GET ${POLARSSL_VERSION_LIST} 2 POLARSSL_VERSION_PATCH)

set(POLARSSL_FOUND True)
mark_as_advanced(
  POLARSSL_FOUND
  POLARSSL_INCLUDE_DIRS
  POLARSSL_LIBRARIES
  POLARSSL_VERSION_MAJOR
  POLARSSL_VERSION_MINOR
  POLARSSL_VERSION_PATCH
  POLARSSL_VERSION_STRING
  POLARSSL_INC_FOLDER
  POLARSSL_REAL_NAME
  )

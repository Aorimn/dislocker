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

include(FindPackageHandleStandardArgs)

find_path(POLARSSL_INCLUDE_DIRS NAMES polarssl/ssl.h)

#
# polarssl -> mbedtls
# Try to find mbedtls.a , if fails tries to find polarssl.
# Only because some distrib (like osx) do not link libmbedtls
# to polarssl for compat
#
find_library(POLARSSL_LIBRARIES NAMES mbedtls)
if(NOT ${POLARSSL_LIBRARIES})
  find_library(POLARSSL_LIBRARIES NAMES polarssl)
endif()

find_package_handle_standard_args(POLARSSL REQUIRED_VARS POLARSSL_INCLUDE_DIRS POLARSSL_LIBRARIES)

if( ${POLARSSL_LIBRARIES-NOTFOUND} )
  message(FATAL_ERROR "Failed to get info from PolarSSL library, check your PolarSSL installation")
  set(POLARSSL_FOUND False)
  return()
endif()

execute_process(
    COMMAND bash -c "echo \"#include <polarssl/version.h>\n#include <stdio.h>\nint main(){printf(POLARSSL_VERSION_STRING);return 0;}\">a.c;cc a.c -I${POLARSSL_INCLUDE_DIRS} ${POLARSSL_LIBRARIES} ;./a.out;rm -f a.c a.out"
    OUTPUT_VARIABLE POLARSSL_VERSION_STRING
    )

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
  )

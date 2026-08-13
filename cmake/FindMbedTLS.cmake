# FindMbedTLS.cmake
# Find the mbedTLS library (works with mbedTLS 2.x and 3.x)
#
# This module defines:
#  MbedTLS_FOUND - True if mbedTLS was found
#  MbedTLS::mbedcrypto - Imported target for mbedcrypto library

include(FindPackageHandleStandardArgs)

# Find the include directory
find_path(MBEDTLS_INCLUDE_DIR
    NAMES mbedtls/ssl.h
    PATHS
        /usr/include
        /usr/local/include
)

# Find the crypto library
find_library(MBEDCRYPTO_LIBRARY
    NAMES mbedcrypto
    PATHS
        /usr/lib
        /usr/lib/aarch64-linux-gnu
        /usr/lib/x86_64-linux-gnu
        /usr/local/lib
)

# Find the TLS library
find_library(MBEDTLS_LIBRARY
    NAMES mbedtls
    PATHS
        /usr/lib
        /usr/lib/aarch64-linux-gnu
        /usr/lib/x86_64-linux-gnu
        /usr/local/lib
)

# Find the X509 library
find_library(MBEDX509_LIBRARY
    NAMES mbedx509
    PATHS
        /usr/lib
        /usr/lib/aarch64-linux-gnu
        /usr/lib/x86_64-linux-gnu
        /usr/local/lib
)

# Get version from version.h
if(MBEDTLS_INCLUDE_DIR)
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" _mbedtls_version_str
         REGEX "^#define[ \t]+MBEDTLS_VERSION_STRING[ \t]+\"[^\"]+\"")
    if(_mbedtls_version_str)
        string(REGEX REPLACE "^#define[ \t]+MBEDTLS_VERSION_STRING[ \t]+\"([^\"]+)\".*" "\\1"
               MBEDTLS_VERSION "${_mbedtls_version_str}")
    endif()
endif()

find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS MBEDCRYPTO_LIBRARY MBEDTLS_INCLUDE_DIR
    VERSION_VAR MBEDTLS_VERSION
)

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::mbedcrypto)
    add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedcrypto PROPERTIES
        IMPORTED_LOCATION "${MBEDCRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIR}"
    )
endif()

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::mbedtls)
    add_library(MbedTLS::mbedtls UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedtls PROPERTIES
        IMPORTED_LOCATION "${MBEDTLS_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIR}"
    )
endif()

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::mbedx509)
    add_library(MbedTLS::mbedx509 UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedx509 PROPERTIES
        IMPORTED_LOCATION "${MBEDX509_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY MBEDTLS_LIBRARY MBEDX509_LIBRARY)

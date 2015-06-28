# Dislocker -- enables to read/write on BitLocker encrypted partitions under
# Linux
# Copyright (C) 2012-2013  Romain Coltel, Hervé Schauer Consultants
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.


add_definitions (-DPROGNAME="${PROJECT_NAME}")
add_definitions (-DAUTHOR="${AUTHOR}")
add_definitions (-DVERSION="${VERSION}")
add_definitions (-D_FILE_OFFSET_BITS=64)
add_definitions (-D__OS="${CMAKE_SYSTEM_NAME}")
string (TOUPPER "${CMAKE_SYSTEM_NAME}" SYSNAME)
add_definitions (-D__${SYSNAME})

if("${CMAKE_SIZEOF_VOID_P}" EQUAL 8)
	add_definitions (-D__ARCH="x86_64")
	add_definitions (-D__ARCH_X86_64)
else()
	add_definitions (-D__ARCH="x86")
	add_definitions (-D__ARCH_X86)
endif()

include_directories (SYSTEM /usr/local/include)
include_directories (${PROJECT_SOURCE_DIR}/include)

set (LIB pthread)
set (SOURCES
		dislocker.c common.c config.c
		xstd/xstdio.c xstd/xstdlib.c
		metadata/datums.c metadata/metadata.c metadata/vmk.c
		metadata/fvek.c metadata/extended_info.c
		metadata/guid.c metadata/print_metadata.c
		accesses/stretch_key.c accesses/accesses.c
		accesses/rp/recovery_password.c
		accesses/user_pass/user_pass.c accesses/bek/bekfile.c
		encryption/encommon.c encryption/decrypt.c encryption/encrypt.c
		encryption/diffuser.c encryption/crc32.c
		ntfs/clock.c ntfs/encoding.c
		inouts/inouts.c inouts/prepare.c inouts/sectors.c
	)

if(NOT DEFINED WARN_FLAGS)
	set (WARN_FLAGS "-Wall -Werror -Wextra" CACHE STRING "" FORCE)
endif()
if(NOT DEFINED HARDEN_FLAGS)
	set (HARDEN_FLAGS "-pie -fPIE -fstack-protector -fstrict-aliasing -D_FORTIFY_SOURCE=2 -O1" CACHE STRING "" FORCE)
endif()

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARN_FLAGS}")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${HARDEN_FLAGS}")

if(DEFINED CFLAGS)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CFLAGS}")
endif()
if(DEFINED RPM_OPT_FLAGS)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${RPM_OPT_FLAGS}")
endif()

set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D DEBUG=${DEBUG} -D__DIS_CORE_DUMPS")


if("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
	# Don't use `-read_only_relocs' here as it seems to only work for 32 bits
	# binaries
	set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-bind_at_load")
	set (FUSE_LIB osxfuse_i64)
else()
	# Useless warnings when used within Darwin
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
	set (FUSE_LIB fuse)
endif()

if(${CMAKE_COMPILER_IS_GNUCC})
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,now -Wl,-z,relro")
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Qunused-arguments")
endif()
if(DEFINED LDFLAGS)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LDFLAGS}")
endif()
if(DEFINED RPM_LD_FLAGS)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${RPM_LD_FLAGS}")
endif()


# Libraries
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package (PolarSSL REQUIRED)
if(POLARSSL_FOUND  AND  POLARSSL_INCLUDE_DIRS  AND  POLARSSL_LIBRARIES)
  include_directories (${POLARSSL_INCLUDE_DIRS})
  set (LIB "${LIB} ${POLARSSL_LIBRARIES}")
else()
  return()
endif()

find_package (Ruby)
if(RUBY_FOUND  AND  RUBY_INCLUDE_DIRS  AND  RUBY_LIBRARIES)
  include_directories (${RUBY_INCLUDE_DIRS})
  set (LIB "${LIB} ${RUBY_LIBRARIES}")
  add_definitions (-D_HAVE_RUBY=${RUBY_VERSION})
endif()

# Places
if(NOT DEFINED sharedir)
  set(sharedir ${CMAKE_INSTALL_PREFIX}/share)
endif()

if(NOT DEFINED mandir)
  set(mandir ${sharedir}/man)
endif()

if(NOT DEFINED libdir)
	if(IS_DIRECTORY "${CMAKE_INSTALL_PREFIX}/lib64")
		set(libdir "${CMAKE_INSTALL_PREFIX}/lib64")
	else()
		set(libdir "${CMAKE_INSTALL_PREFIX}/lib")
	endif()
endif()

if(NOT DEFINED bindir)
	set(bindir "${CMAKE_INSTALL_PREFIX}/bin")
endif()

string (TOLOWER "${CMAKE_SYSTEM_NAME}" SYSNAME)
set (DIS_MAN ../man/${SYSNAME})

# RPATH handling
set (CMAKE_SKIP_BUILD_RPATH  FALSE)
set (CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set (CMAKE_INSTALL_RPATH "${libdir}")
set (CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
# RPATH to be used when installing, but only if it's not a system directory
list (FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${libdir}" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
	set (CMAKE_INSTALL_RPATH "${libdir}")
endif()

# Targets
add_library (${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries (${PROJECT_NAME} ${LIB})
set_target_properties (${PROJECT_NAME} PROPERTIES VERSION "${VERSION}" SOVERSION "${VERSION_MAJOR}")
install (TARGETS ${PROJECT_NAME} LIBRARY DESTINATION "${libdir}")

set (CLEAN_FILES "")

set (BIN_FUSE ${PROJECT_NAME}-fuse)
add_executable (${BIN_FUSE} ${BIN_FUSE}.c)
target_link_libraries (${BIN_FUSE} ${FUSE_LIB} ${PROJECT_NAME})
set_target_properties (${BIN_FUSE} PROPERTIES COMPILE_DEFINITIONS FUSE_USE_VERSION=26)
add_custom_command (TARGET ${BIN_FUSE} POST_BUILD
	COMMAND gzip -c ${DIS_MAN}/${BIN_FUSE}.1 > ${DIS_MAN}/${BIN_FUSE}.1.gz
)
set (CLEAN_FILES ${CLEAN_FILES} ${DIS_MAN}/${BIN_FUSE}.1.gz)
install (TARGETS ${BIN_FUSE} RUNTIME DESTINATION "${bindir}")
install (FILES ${DIS_MAN}/${BIN_FUSE}.1.gz DESTINATION "${mandir}/man1")

set (BIN_FILE ${PROJECT_NAME}-file)
add_executable (${BIN_FILE} ${BIN_FILE}.c)
target_link_libraries (${BIN_FILE} ${PROJECT_NAME})
add_custom_command (TARGET ${BIN_FILE} POST_BUILD
	COMMAND gzip -c ${DIS_MAN}/${BIN_FILE}.1 > ${DIS_MAN}/${BIN_FILE}.1.gz
)
set (CLEAN_FILES ${CLEAN_FILES} ${DIS_MAN}/${BIN_FILE}.1.gz)
install (TARGETS ${BIN_FILE} RUNTIME DESTINATION "${bindir}")
install (FILES ${DIS_MAN}/${BIN_FILE}.1.gz DESTINATION "${mandir}/man1")

set (BIN_METADATA ${PROJECT_NAME}-metadata)
add_executable (${BIN_METADATA} ${BIN_METADATA}.c)
target_link_libraries (${BIN_METADATA} ${PROJECT_NAME})
install (TARGETS ${BIN_METADATA} RUNTIME DESTINATION "${bindir}")

set (BIN_BEK ${PROJECT_NAME}-bek)
add_executable (${BIN_BEK} ${BIN_BEK}.c)
target_link_libraries (${BIN_BEK} ${PROJECT_NAME})
install (TARGETS ${BIN_BEK} RUNTIME DESTINATION "${bindir}")

if(RUBY_FOUND)
	set (BIN_FIND ${PROJECT_NAME}-find)
	add_custom_target(${BIN_FIND} ALL
		COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/${BIN_FIND}.rb" "${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND}"
		COMMAND sed -e 's&@SED_LIBDIR_PLACEHOLDER@&${libdir}&' -i "${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND}"
		COMMAND chmod u+x "${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND}"
		SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/${BIN_FIND}.rb"
	)
	set (CLEAN_FILES ${CLEAN_FILES} ${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND})
	add_custom_command (TARGET ${BIN_FIND} POST_BUILD
		COMMAND gzip -c ${DIS_MAN}/${BIN_FIND}.1 > ${DIS_MAN}/${BIN_FIND}.1.gz
	)
	set (CLEAN_FILES ${CLEAN_FILES} ${DIS_MAN}/${BIN_FIND}.1.gz)
	install (PROGRAMS ${BIN_FIND} DESTINATION "${bindir}")
	install (FILES ${DIS_MAN}/${BIN_FIND}.1.gz DESTINATION "${mandir}/man1")
else()
	set (BIN_FIND true)
endif()

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")

# Travis' test target
add_custom_target(travis-test
	COMMAND ${BIN_FUSE} -h
	COMMAND ${BIN_FILE} -h
	COMMAND ${BIN_METADATA} -h
	COMMAND ${BIN_BEK} -h
	COMMAND ${BIN_FIND} -h
	COMMAND man -w dislocker
)

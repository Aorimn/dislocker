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

if("${CMAKE_SOURCE_DIR}" MATCHES "src/?$")
	message(FATAL_ERROR "\nPlease execute cmake from the directory above, not the src/ directory.")
	return()
endif()

# On OSX, frameworks are found before installed libraries (cf. https://gitlab.kitware.com/cmake/cmake/-/issues/16427)
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
	set(CMAKE_FIND_FRAMEWORK Last)
	message(STATUS "CMAKE_FIND_FRAMEWORK='${CMAKE_FIND_FRAMEWORK}'")
endif()

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

if( NOT CMAKE_CROSSCOMPILING )
	include_directories (SYSTEM /usr/local/include)
endif()
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
		encryption/diffuser.c encryption/crc32.c encryption/aes-xts.c
		ntfs/clock.c ntfs/encoding.c
		inouts/inouts.c inouts/prepare.c inouts/sectors.c
	)

if(NOT DEFINED WARN_FLAGS)
	set (WARN_FLAGS "-Wall -Wextra" CACHE STRING "" FORCE)
endif()
if(NOT DEFINED HARDEN_FLAGS)
	set (HARDEN_FLAGS "-fstack-protector -fstrict-aliasing -D_FORTIFY_SOURCE=2 -O1" CACHE STRING "" FORCE)
endif()

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
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
	# Library for libiconv
	set (LIB ${LIB} iconv)
else()
	# Useless warnings when used within Darwin
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
	if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
		link_directories ( ${LINK_DIRECTORIES} /usr/local/lib )
	endif()
endif()

if(${CMAKE_COMPILER_IS_GNUCC})
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,now -Wl,-z,relro")
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Qunused-arguments")
else()
	message ("*** WARNING *** You're compiling with an untested compiler (${CMAKE_C_COMPILER_ID}), this mays result in unwanted behaviours.\n")
endif()
if(DEFINED LDFLAGS)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LDFLAGS}")
endif()
if(DEFINED RPM_LD_FLAGS)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${RPM_LD_FLAGS}")
endif()


# Libraries
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package (MbedTLS REQUIRED)
set (LIB ${LIB} MbedTLS::mbedcrypto)

# Ruby bindings
set(WITH_RUBY "AUTO" CACHE STRING "Enable Ruby bindings. Valid values are ON, OFF, or AUTO")
if (NOT "${WITH_RUBY}" STREQUAL "OFF")
	set(_Ruby_DEBUG_OUTPUT ON)
	find_package (Ruby)
	if(RUBY_FOUND  AND  RUBY_INCLUDE_DIRS  AND  RUBY_LIBRARY)
		include_directories(${RUBY_INCLUDE_DIRS})
		set(LIB ${LIB} ${RUBY_LIBRARY})
		add_definitions(-D_HAVE_RUBY=${RUBY_VERSION_STRING})
		set(SOURCES ${SOURCES} ruby.c)
	elseif("${WITH_RUBY}" STREQUAL "ON")
		message(FATAL_ERROR "Ruby bindings requested, but Ruby could not found")
	else()
		message("Ruby not found, Ruby bindings will be disabled")
	endif()
else()
	message("Ruby bindings disabled by user request")
endif()

# FUSE
# Unlike Ruby which is largely optional, the primary use-case of Dislocker depends on FUSE,
# so fail when its not found unless explicitly disabled by the user.
option(WITH_FUSE "Enable FUSE support. Required for mounting BitLocker-encrypted volumes" ON)
if(WITH_FUSE)
	find_package (FUSE)
	if(FUSE_FOUND  AND  FUSE_INCLUDE_DIRS  AND  FUSE_LIBRARIES)
		include_directories (${FUSE_INCLUDE_DIRS})
		if(FUSE_LIBRARY_DIRS)
			link_directories(${FUSE_LIBRARY_DIRS})
		endif()
		set (LIB ${LIB} ${FUSE_LIBRARIES})
	else()
		message(FATAL_ERROR "FUSE not found. Please install FUSE, or configure Dislocker with -DWITH_FUSE=OFF")
	endif()
else()
	message(WARNING "FUSE support is disabled, Dislocker will be unable to mount BitLocker-encrypted volumes!")
endif()

# Places
if(NOT DEFINED sharedir)
  set(sharedir ${CMAKE_INSTALL_PREFIX}/share)
endif()

if(NOT DEFINED mandir)
  set(mandir ${sharedir}/man)
endif()

if(NOT DEFINED LIB_INSTALL_DIR)
	if(NOT DEFINED libdir)
		if(IS_DIRECTORY "${CMAKE_INSTALL_PREFIX}/lib64")
			set(libdir "${CMAKE_INSTALL_PREFIX}/lib64")
		else()
			set(libdir "${CMAKE_INSTALL_PREFIX}/lib")
		endif()
	endif()
else()
	set(libdir ${LIB_INSTALL_DIR})
endif()

if(NOT DEFINED bindir)
	set(bindir "${CMAKE_INSTALL_PREFIX}/bin")
endif()

string (TOLOWER "${CMAKE_SYSTEM_NAME}" SYSNAME)
set (DIS_MAN ${PROJECT_SOURCE_DIR}/man/${SYSNAME})

# RPATH handling
if(POLICY CMP0042)
	cmake_policy (SET CMP0042 NEW)
endif()
set (CMAKE_SKIP_BUILD_RPATH FALSE)
set (CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set (CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
list (FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${libdir}" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
   set (CMAKE_INSTALL_RPATH "${libdir}")
endif()

# Targets
add_library (${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries (${PROJECT_NAME} ${LIB})
set_target_properties (${PROJECT_NAME} PROPERTIES VERSION "${VERSION}" SOVERSION "${VERSION_MAJOR}.${VERSION_MINOR}")
install (TARGETS ${PROJECT_NAME} LIBRARY DESTINATION "${libdir}")

if (${APPLE})
	set (BUNDLE_NAME ${PROJECT_NAME}_bundle)
	add_library (${BUNDLE_NAME} MODULE ${SOURCES})
	target_link_libraries (${BUNDLE_NAME} ${LIB})
	set_target_properties (${BUNDLE_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME} SUFFIX .bundle)
	install (TARGETS ${BUNDLE_NAME} DESTINATION "${libdir}")
endif()

set (CLEAN_FILES "")

if(FUSE_FOUND)
	set (BIN_FUSE ${PROJECT_NAME}-fuse)
	add_executable (${BIN_FUSE} ${BIN_FUSE}.c)
	target_link_libraries (${BIN_FUSE} ${FUSE_LIBBRARIES} ${PROJECT_NAME})
	set_target_properties (${BIN_FUSE} PROPERTIES COMPILE_DEFINITIONS FUSE_USE_VERSION=314)
	set_target_properties (${BIN_FUSE} PROPERTIES LINK_FLAGS "-pie -fPIE")
	add_custom_command (TARGET ${BIN_FUSE} POST_BUILD
		COMMAND mkdir -p ${CMAKE_BINARY_DIR}/man/
		COMMAND gzip -c ${DIS_MAN}/${BIN_FUSE}.1 > ${CMAKE_BINARY_DIR}/man/${BIN_FUSE}.1.gz
	)
	set (CLEAN_FILES ${CLEAN_FILES} ${CMAKE_BINARY_DIR}/man/${BIN_FUSE}.1.gz)
	install (TARGETS ${BIN_FUSE} RUNTIME DESTINATION "${bindir}")
	install (FILES ${CMAKE_BINARY_DIR}/man/${BIN_FUSE}.1.gz DESTINATION "${mandir}/man1")
	install (CODE "execute_process (COMMAND ${CMAKE_COMMAND} -E create_symlink ${BIN_FUSE} \"\$ENV{DESTDIR}${bindir}/${PROJECT_NAME}\")")
	install (CODE "execute_process (COMMAND ${CMAKE_COMMAND} -E create_symlink ${BIN_FUSE}.1.gz \"\$ENV{DESTDIR}${mandir}/man1/${PROJECT_NAME}.1.gz\")")
endif()

set (BIN_FILE ${PROJECT_NAME}-file)
add_executable (${BIN_FILE} ${BIN_FILE}.c)
target_link_libraries (${BIN_FILE} ${PROJECT_NAME})
set_target_properties (${BIN_FILE} PROPERTIES LINK_FLAGS "-pie -fPIE")
add_custom_command (TARGET ${BIN_FILE} POST_BUILD
	COMMAND mkdir -p ${CMAKE_BINARY_DIR}/man/
	COMMAND gzip -c ${DIS_MAN}/${BIN_FILE}.1 > ${CMAKE_BINARY_DIR}/man/${BIN_FILE}.1.gz
)
set (CLEAN_FILES ${CLEAN_FILES} ${CMAKE_BINARY_DIR}/man/${BIN_FILE}.1.gz)
install (TARGETS ${BIN_FILE} RUNTIME DESTINATION "${bindir}")
install (FILES ${CMAKE_BINARY_DIR}/man/${BIN_FILE}.1.gz DESTINATION "${mandir}/man1")

set (BIN_METADATA ${PROJECT_NAME}-metadata)
add_executable (${BIN_METADATA} ${BIN_METADATA}.c)
target_link_libraries (${BIN_METADATA} ${PROJECT_NAME})
set_target_properties (${BIN_METADATA} PROPERTIES LINK_FLAGS "-pie -fPIE")
install (TARGETS ${BIN_METADATA} RUNTIME DESTINATION "${bindir}")

set (BIN_BEK ${PROJECT_NAME}-bek)
add_executable (${BIN_BEK} ${BIN_BEK}.c)
target_link_libraries (${BIN_BEK} ${PROJECT_NAME})
set_target_properties (${BIN_BEK} PROPERTIES LINK_FLAGS "-pie -fPIE")
install (TARGETS ${BIN_BEK} RUNTIME DESTINATION "${bindir}")

set (BIN_RECOVERY ${PROJECT_NAME}-recovery)
add_executable (${BIN_RECOVERY} ${BIN_RECOVERY}.c)
target_link_libraries (${BIN_RECOVERY} ${PROJECT_NAME})
set_target_properties (${BIN_RECOVERY} PROPERTIES LINK_FLAGS "-pie -fPIE")
install (TARGETS ${BIN_RECOVERY} RUNTIME DESTINATION "${bindir}")

if(RUBY_FOUND)
	set (BIN_FIND ${PROJECT_NAME}-find)
	configure_file ("${CMAKE_CURRENT_SOURCE_DIR}/${BIN_FIND}.rb.in" "${CMAKE_CURRENT_SOURCE_DIR}/${BIN_FIND}.rb" ESCAPE_QUOTES @ONLY)
	add_custom_target(${BIN_FIND} ALL
		COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/${BIN_FIND}.rb" "${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND}"
		COMMAND chmod u+x "${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND}"
		SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/${BIN_FIND}.rb"
	)
	set (CLEAN_FILES ${CLEAN_FILES} ${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND})
	add_custom_command (TARGET ${BIN_FIND} POST_BUILD
		COMMAND mkdir -p ${CMAKE_BINARY_DIR}/man/
		COMMAND gzip -c ${DIS_MAN}/${BIN_FIND}.1 > ${CMAKE_BINARY_DIR}/man/${BIN_FIND}.1.gz
	)
	set (CLEAN_FILES ${CLEAN_FILES} ${CMAKE_BINARY_DIR}/man/${BIN_FIND}.1.gz)
	install (PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${BIN_FIND} DESTINATION "${bindir}")
	install (FILES ${CMAKE_BINARY_DIR}/man/${BIN_FIND}.1.gz DESTINATION "${mandir}/man1")
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

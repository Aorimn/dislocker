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

cmake_minimum_required (VERSION 2.6)
project (dislocker C)

set (AUTHOR "Romain Coltel")

find_program (GIT_EXE NAMES git PATHS /usr/bin /usr/local/bin)

if(GIT_EXE)
	execute_process (
		COMMAND ${GIT_EXE} rev-parse --abbrev-ref HEAD
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		OUTPUT_VARIABLE GIT_RELEASE_BRANCH
	)
	execute_process (
		COMMAND ${GIT_EXE} log -n 1 --pretty=format:%t
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		OUTPUT_VARIABLE GIT_RELEASE_COMMIT
	)
	string (STRIP "${GIT_RELEASE_BRANCH}" GIT_RELEASE_BRANCH)
	string (STRIP "${GIT_RELEASE_COMMIT}" GIT_RELEASE_COMMIT)
	add_definitions (-DVERSION_DBG="${GIT_RELEASE_BRANCH}:${GIT_RELEASE_COMMIT}")
endif()


set (VERSION_MAJOR 0)
set (VERSION_MINOR 7)
set (VERSION_RELEASE 2)
set (VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_RELEASE}")

add_subdirectory (${PROJECT_SOURCE_DIR}/src)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY
)
add_custom_target(uninstall
	COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
)

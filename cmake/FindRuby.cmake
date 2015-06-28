# Ruby cmake package
#
# Returns
# RUBY_FOUND
# RUBY_INCLUDE_DIRS
# RUBY_LIBRARIES
# RUBY_VERSION_MAJOR
# RUBY_VERSION_MINOR
# RUBY_VERSION_STRING

if(RUBY_FOUND)
   set(RUBY_FIND_QUIETLY TRUE)
endif()

find_program(RUBY_EXECUTABLE
  NAMES ruby2.2 ruby22 ruby2.1 ruby21 ruby2.0 ruby2 ruby1.9.3 ruby193 ruby1.9.2 ruby192 ruby1.9.1 ruby191 ruby1.9 ruby19 ruby1.8 ruby18 ruby
  PATHS /usr/bin /usr/local/bin /usr/pkg/bin
  )
if(RUBY_EXECUTABLE)
  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['MAJOR']"
    OUTPUT_VARIABLE RUBY_VERSION_MAJOR
    )

  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['MINOR']"
    OUTPUT_VARIABLE RUBY_VERSION_MINOR
    )

  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['TEENY']"
    OUTPUT_VARIABLE RUBY_VERSION_TEENY
    )
  set(RUBY_VERSION_STRING ${RUBY_VERSION_MAJOR}.${RUBY_VERSION_MINOR}.${RUBY_VERSION_TEENY})

  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['rubyhdrdir'] || RbConfig::CONFIG['archdir']"
    OUTPUT_VARIABLE RUBY_ARCH_DIR
    )
  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['arch']"
    OUTPUT_VARIABLE RUBY_ARCH
    )
  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['libdir']"
    OUTPUT_VARIABLE RUBY_POSSIBLE_LIB_PATH
    )
  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['rubylibdir']"
    OUTPUT_VARIABLE RUBY_LIB_PATH
    )
  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['archincludedir']"
    OUTPUT_VARIABLE RUBY_ARCH_INC_DIR
    )
  execute_process(
    COMMAND ${RUBY_EXECUTABLE} -r rbconfig -e "print RbConfig::CONFIG['RUBY_SO_NAME']"
    OUTPUT_VARIABLE RUBY_SO_NAME
    )

  find_path(RUBY_INCLUDE_DIRS
    NAMES ruby.h ruby/config.h
    PATHS ${RUBY_ARCH_DIR}
    )
  set(RUBY_INCLUDE_ARCH "${RUBY_INCLUDE_DIRS}/${RUBY_ARCH}")
  find_library(RUBY_LIB
    NAMES ${RUBY_SO_NAME}
    PATHS ${RUBY_POSSIBLE_LIB_PATH} ${RUBY_RUBY_LIB_PATH}
    )

  if(RUBY_LIB AND RUBY_INCLUDE_DIRS)
    set(RUBY_FOUND TRUE)
    set(RUBY_INCLUDE_DIRS "${RUBY_INCLUDE_DIRS};${RUBY_INCLUDE_ARCH};${RUBY_ARCH_INC_DIR}/ruby-${RUBY_VERSION_STRING}")
    set(RUBY_LIBRARIES ${RUBY_LIB})
  endif()

  if(RUBY_OLD_VERSION)
    set(RUBY_FOUND FALSE)
    set(RUBY_NOT_FOUND TRUE)
  endif()

  mark_as_advanced(
    RUBY_INCLUDE_DIRS
    RUBY_LIBRARIES
    RUBY_LIB
    RUBY_VERSION_MAJOR RUBY_VERSION_MINOR
    RUBY_VERSION_STRING
    )
endif()

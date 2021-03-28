# Find the FUSE includes and library
#
#  FUSE_INCLUDE_DIRSS - where to find fuse.h, etc.
#  FUSE_LIBRARIES   - List of libraries when using FUSE.
#  FUSE_FOUND       - True if FUSE lib is found.

# check if already in cache, be silent
IF (FUSE_INCLUDE_DIRS)
        SET (FUSE_FIND_QUIETLY TRUE)
ENDIF (FUSE_INCLUDE_DIRS)

FIND_PACKAGE (PkgConfig REQUIRED)
pkg_check_modules (FUSE REQUIRED fuse)

mark_as_advanced (FUSE_INCLUDE_DIRS FUSE_LIBRARIES FUSE_LIBRARY_DIRS)

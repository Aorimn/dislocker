FILESEXTRAPATHS_prepend := "${THISDIR}/dislocker:"

SUMMARY = "Read BitLocker encrypted partitions under a Linux system"
DESCRIPTION = " \
This software has been designed to read BitLocker encrypted partitions under a \
Linux system. The driver has the capability to read/write on: \
 - Windows Vista, 7, 8, 8.1 and 10 encrypted partitions; \
 - BitLocker-To-Go encrypted partitions - that's USB/FAT32 partitions. \
"

HOMEPAGE = "http://www.hsc.fr/ressources/outils/dislocker/index.html.en"
BUGTRACKER = "https://github.com/Aorimn/dislocker/issues"

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://LICENSE.txt;md5=6aa0d8e41ad2e57bef0712adf0cf5cb5"

SECTION = "e/utils"

SRC_URI = "\
  http://www.hsc.fr/ressources/outils/dislocker/download/dislocker-${PV}.tar.gz \
  file://find_polar_ssl.patch;apply=true \
  file://src_cmake_lists.patch;apply=true \
  "

SRC_URI[md5sum] = "5bc9de345c17fff15a4c008f4100a8fa"
SRC_URI[sha256sum] = "e125e3b23d6c1cc2ee2b01958dceaaa15a28ae5616a7cb38b973c5befdb16ead"

DEPENDS = "mbedtls fuse"
RDEPENDS_${PN} += "mbedtls fuse"
PROVIDES += "dislocker"
RPROVIDES_${PN} = "dislocker"
EXTRA_OECMAKE = " -DLIB_INSTALL_DIR=${baselib}"

inherit cmake

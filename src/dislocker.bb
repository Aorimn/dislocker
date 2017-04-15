FILESEXTRAPATHS_prepend := "${THISDIR}/dislocker:"

SUMMARY = "Read BitLocker encrypted partitions under a Linux system"
DESCRIPTION = " \
This software has been designed to read BitLocker encrypted partitions under a \
Linux system. The driver has the capability to read/write on: \
 - Windows Vista, 7, 8, 8.1 and 10 encrypted partitions - that's AES-CBC, \
   AES-XTS, 128 or 256 bits, with or without the Elephant diffuser, encrypted \
   partitions; \
 - BitLocker-To-Go encrypted partitions - that's USB/FAT32 partitions. \
"

HOMEPAGE = "https://github.com/Aorimn/dislocker"
BUGTRACKER = "https://github.com/Aorimn/dislocker/issues"

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://LICENSE.txt;md5=6aa0d8e41ad2e57bef0712adf0cf5cb5"

SECTION = "e/utils"

SRC_URI = "https://github.com/Aorimn/dislocker/archive/v${PV}.tar.gz"

SRC_URI[md5sum] = "0683bd18472d5f9e13f718e4d80ed7c7"
SRC_URI[sha256sum] = "9e36afb0b29714e325d1721332e913bbd357f089a53962fcb7ae62f2e3862d84"

DEPENDS = "mbedtls fuse"
RDEPENDS_${PN} += "mbedtls fuse"
PROVIDES += "dislocker"
RPROVIDES_${PN} = "dislocker"
EXTRA_OECMAKE = " -DLIB_INSTALL_DIR=${baselib}"

inherit cmake

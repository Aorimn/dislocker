INTRODUCTION AND EXPLANATIONS
`-----------------------------

This software has been designed to read BitLocker encrypted partitions under a
Linux system. The driver used to only read volumes encrypted under a Windows 7
system but is now Windows Vista and 8 capable and has the write functionality.

The driver can run into two different modes : with or without FUSE. This mode is
decided at compilation time within the Makefile.

With FUSE, you have to give the program a mount point. Once keys are decrypted,
a file named `dislocker-file' appears into this provided mount point. This file
is a virtual NTFS partition, so you can mount it as any NTFS partition and then
read from it or write to it.

Without FUSE, you have to give a file name where the BitLocker encrypted
partition will be decrypted. This may take a long time, depending on the size of
the encrypted partition. But afterward, once the partition is decrypted, the
access to the NTFS partition will be faster. Another thing to think about is the
size on your disk this method need (same size as the volume you're trying to
decrypt). Nethertheless, once the partition is decrypted, you can mount your
file as any NTFS partition.



INSTALLATION AND REQUIREMENTS
`-----------------------------

See INSTALL.txt for things dealing with the install process.
Once installed, see dislocker(1) for details on how to use it.



BUGS
`----

There may be bugs, and I'll be happy to hear about it!
A precise test table is present into the INSTALL.txt file.

Feel free to send comments and feedbacks to <dislocker __AT__ hsc __DOT__ fr>.



NOTE
`----

In many directories included into the sources, there's a Makefile with rules to
build a standalone binary. To build these standalone binaries, cd to the
directory and type `make`, thus creating a binary which you can use to do some
process separately.

Binary capable directories:
- accesses/bek/: read a .bek file and display information about it;
- accesses/rp/: calculate the intermediate key for a given recovery password;
- metadata/: read a BitLocker volume and display information about its metadata;
- outputs/fuse/: FUSE's hello world example.



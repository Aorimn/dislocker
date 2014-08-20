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
read from it or write to it. Note that writing to the NTFS virtual file will
change the underlying BitLocker partition's content.

Without FUSE, you have to give a file name where the BitLocker encrypted
partition will be decrypted. This file will be the decrypted partition,
probably formatted in NTFS. It won't have any link to the original BitLocker
partition. Therefore, if you write on this file, the BitLocker volume won't
change, only the NTFS file will. Note that this may take a long time, depending
on the size of the encrypted partition. But afterward, once the partition is
decrypted, the access to the NTFS partition will be faster. Another thing to
think about is the size on your disk this method need (same size as the volume
you're trying to decrypt). Nethertheless, once the partition is decrypted, you
can mount your file as any NTFS partition.



INSTALLATION AND REQUIREMENTS
`-----------------------------

See INSTALL.txt for things dealing with the install process.
Once installed, see dislocker(1) for details on how to use it.



BUGS
`----

There may be bugs, and I'll be happy to hear about it!

Feel free to send comments and feedbacks to <dislocker __AT__ hsc __DOT__ fr>.



NOTE
`----

Two more binaries are build when compiling dislocker:
- One for disecting a .bek file and printing information about it;
- The other one for printing information about a BitLocker-encrypted volume.


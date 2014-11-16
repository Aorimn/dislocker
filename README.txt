INTRODUCTION AND EXPLANATIONS
`-----------------------------

This software has been designed to read BitLocker encrypted partitions under a
Linux system. The driver used to only read volumes encrypted under a Windows 7
system but is now Windows Vista and 8 capable and has the write functionality.

The core driver is composed of a library, with multiple binaries (see the NOTES
section below) using this library. Two binaries are of interest when wanting to
decrypt a BitLocker encrypted partition:

. dislocker-fuse: binary using FUSE to dynamically decrypt the BitLocker-ed
partition. You have to give it a mount point where, once keys are decrypted, a
file named `dislocker-file' appears. This file is a virtual NTFS partition, so
you can mount it as any NTFS partition and then read from or write to it. Note
that writing to the NTFS virtual file will change the underlying BitLocker
partition's content.

. dislocker-file: binary decrypting a BitLocker encrypted partition into a flat
file. This file has to be given through commandline and, once dislocker-file is
finished, will be an NTFS partition. It won't have any link to the original
BitLocker partition. Therefore, if you write to this file, the BitLocker volume
won't change, only the NTFS file will. Note that this may take a long time to
create that file, depending on the size of the encrypted partition. But
afterward, once the partition is decrypted, the access to the NTFS partition
will be faster. Another thing to think about os the size on your disk this
binary needs: the same size as the volume you're trying to decrypt.
Nethertheless, once the partition is decrypted, you can mount your file as any
NTFS partition.


Thanks goes to Rogier Wolff for testing, hugsy for all the OSX support and
patches, Will Dyson for the patches, and all the people who give feedbacks.



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

Four binaries are built when compiling dislocker as described in the INSTALL.txt
file:
- One for disecting a .bek file and printing information about it
  dislocker-bek
- Another one for printing information about a BitLocker-encrypted volume
  dislocker-metadata
- A third one for decrypting a BitLocker encrypted partition into a flat file
formatted as an NTFS partition you can mount
  dislocker-file
- A last one, which is the one you're using when calling `dislocker',
dynamically decrypts a BitLocker encrypted partition using FUSE
  dislocker-fuse

You can build each one independently providing it as the makefile target. For
instance, if you want to compile dislocker-fuse only, you'd simply run:
  make dislocker-fuse
To install this binary only, you would then run the following command:
  make install BINS=dislocker-fuse


# Dislocker [![Build Status](https://travis-ci.org/Aorimn/dislocker.svg?branch=develop)](https://travis-ci.org/Aorimn/dislocker)

## Introduction and explanations

This software has been designed to read BitLocker encrypted partitions under a
Linux system. The driver has the capability to read/write on:
 - Windows Vista, 7, 8, 8.1 and 10 encrypted partitions - that's AES-CBC,
   AES-XTS, 128 or 256 bits, with or without the Elephant diffuser, encrypted
   partitions;
 - BitLocker-To-Go encrypted partitions - that's USB/FAT32 partitions.

The core driver is composed of a library, with multiple binaries (see the NOTES
section below) using this library. Two binaries are of interest when wanting to
decrypt a BitLocker encrypted partition:

1. `dislocker-fuse`: binary using FUSE to dynamically decrypt the BitLocker-ed
partition. You have to give it a mount point where, once keys are decrypted, a
file named `dislocker-file` appears. This file is a virtual NTFS partition, so
you can mount it as any NTFS partition and then read from or write to it. Note
that writing to the NTFS virtual file will change the underlying BitLocker
partition's content.

2. `dislocker-file`: binary decrypting a BitLocker encrypted partition into a flat
file. This file has to be given through command line and, once dislocker-file is
finished, will be an NTFS partition. It won't have any link to the original
BitLocker partition. Therefore, if you write to this file, the BitLocker volume
won't change, only the NTFS file will. Note that this may take a long time to
create that file, depending on the size of the encrypted partition. But
afterward, once the partition is decrypted, the access to the NTFS partition
will be faster. Another thing to think about is the size on your disk this
binary needs: the same size as the volume you're trying to decrypt.
Nevertheless, once the partition is decrypted, you can mount your file as any
NTFS partition.

Thanks goes to Rogier Wolff for testing, hugsy for all the OSX support and
patches, Will Dyson for the patches, and all the people who give feedbacks.

## Installation and requirements

See `INSTALL.md` for things dealing with the install process.
Once installed, see `dislocker(1)` for details on how to use it.

## Bugs

There may be bugs, and I'll be happy to hear about it!

Feel free to send comments and feedbacks to [dislocker __AT__ hsc __DOT__ fr](),
or to open an [issue](https://github.com/Aorimn/dislocker/issues).

## A note on Bitlocker-To-Go

Microsoft's idea behind BitLocker-To-Go is that computers running Microsoft
operating systems will be able to mount encrypted removable media without too
much trouble.

To achieve this, the data on the media has a dual format. First it is
a valid FAT32 filesystem. In that filesystem they store executables and
datafiles that allow access to the encrypted volume. Besides that you
will see big "encrypted" files that hold the actual encrypted volume.

On the other side, it is a BitLocker volume. Just with some unused space, from
the BitLocker point-of-view. That's where the FAT32 stuff lives.

So, to access a  BitLocker-To-Go encrypted media, the whole partition is the
volume that dislocker works with. The use of dislocker is therefore the same
whether the volume is a standard BitLocker partition or a BitLocker-To-Go one.

## A note on fstab

BitLocker partitions can be mount-ed using the /etc/fstab file and dislocker's
long options.
The line below is an example line, which has to be adapted to each case:
```
/dev/sda2 /mnt/dislocker fuse.dislocker user-password=blah,nofail 0 0
```

## Note

Five binaries are built when compiling dislocker as described in the `INSTALL.md`
file:

1. `dislocker-bek`: for dissecting a .bek file and printing information about it

2. `dislocker-metadata`: for printing information about a BitLocker-encrypted volume

3. `dislocker-find`: not a binary but a Ruby script which tries to find BitLocker
  encrypted partition among the plugged-in disks (only work if the library is
  compiled with the Ruby bindings)

4. `dislocker-file`: for decrypting a BitLocker encrypted partition into a flat file
formatted as an NTFS partition you can mount

5. `dislocker-fuse`: the one you're using when calling `dislocker',
which dynamically decrypts a BitLocker encrypted partition using FUSE

You can build each one independently providing it as the makefile target. For
instance, if you want to compile dislocker-fuse only, you'd simply run:
```bash
$ cmake .
$ make dislocker-fuse
```

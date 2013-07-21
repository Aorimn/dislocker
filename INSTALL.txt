INTRODUCTION
`------------

This file describes how to install dislocker onto your machine.



REQUIREMENTS
`------------

You need:
 - Package libfuse-dev (debian), fuse-devel (fedora) or osxfuse (OSX), if you
   want to use FUSE;
 - A partition encrypted with BitLocker, from Windows Vista or 7.

Of course, you need a compiler (tested against gcc 4.6 and darwin 10-4.2.1).

Note that the code expects FUSE 2.6, when using the decryption with FUSE.



INSTALLING
`----------

First thing to do is to cd into the src/ directory. Then...

As you may know, the driver can be used in two ways: using FUSE or not. By
default, typing `make` will generate a FUSE capable binary. However, running
`make file` won't include FUSE capabilities. In this latter mode, dislocker
will decrypt your BitLocker volume into a file, so make sure you have enough
space left on your partition. The file will be a NTFS partition then.
Thus, make your choice of the use you'll have.

Type: `make` or `make file` according to your needs, then `sudo make install`
(or just the last one if you're lazy, but I don't recommend that). Note that the
`-Werror' flag on the `WFLAGS' line in the Makefile may break the compilation,
so you can remove it, but it is as your own risks.

The binary will be installed into `/usr/bin/' by default, edit the INSTALL_PATH
variable (into the Makefile) to change that before the `make install` command.

Once installed, see dislocker(1) for details on how to use it.



UNINSTALLING
`------------

I'm sure you don't want to do that. But if you're really forced by someone, just
type `make uninstall`.



PORTABILITY
`-----------

Globally, this was successfuly tested on Linux x86/x86_64. It won't work on
Windows and may not work on *BSD (never tested).

Precisely, the table below indicates distrib, version and arch:

+----------------------------------------------------+
| distrib/OS  | version |  arch  | Vista(v)/Seven(s) |
|-------------+---------+--------+-------------------|
| Fedora      |   14    | x86_64 |         s         |
| Fedora      |   15    | x86    |        vs         |
| Fedora      |   15    | x86_64 |        vs         |
| Fedora      |   16    | x86    |        vs         |
| Fedora      |   16    | x86_64 |        vs         |
| Ubuntu      |  11.04  | x86    |         s         |
| MacOSX      | 10.6.8  | i386   |        vs         |
+----------------------------------------------------+

Note: For MacOSX, it has been tested against OSXFUSE 2.3.8 and 2.3.9.

If your distrib/OS isn't in that table, this doesn't imply that the driver
doesn't work for you. Test it and send me feedbacks, whether it works or not.

In any case, feel free to send comments and feedbacks to
<dislocker __AT__ hsc __DOT__ fr>.

Thanks goes to Rogier Wolff for testing.



NOTE
`----

In many directories included into the sources, there's a Makefile with rules to
build a standalone binary. To build these standalone binaries, cd to the
directory and type `make`, thus creating a binary which you can use to do some
process separately.

Binary capable directories:
- accesses/bek/: read a .bek file and display information about it;
- accesses/rp/: calculate the intermediate key for a given recovery password;
- encryption/: test encryption/decryption on a test case;
- metadata/: read a BitLocker volume and display information about its metadata;
- outputs/fuse/: FUSE's hello world example.

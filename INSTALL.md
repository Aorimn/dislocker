# INTRODUCTION

This file describes how to install dislocker onto your machine.

# REQUIREMENTS

You need:

- Compiler, gcc or clang;
- cmake (at least version 2.6);
- make (or gmake, for FreeBSD);
- Headers for FUSE;
- Headers for mbedTLS (previously known as PolarSSL);
- A partition encrypted with BitLocker, from Windows Vista, 7 or 8.


If you have Ruby headers, the library will compile with some Ruby bindings and
another program - see the NOTE section below - will be available.

For Debian-like distos based on Debian Jessie or Ubuntu 14.04 or older:

- `aptitude install gcc cmake make libfuse-dev libpolarssl-dev ruby-dev`

For Debian-like distos based on Debian Stretch or Ubuntu 16.04 or later:

- `aptitude install gcc cmake make libfuse-dev libmbedtls-dev ruby-dev`

For Fedora-like:

- `dnf install gcc cmake make fuse-devel mbedtls-devel ruby-devel rubypick`

Alternatively, running `dnf install dislocker fuse-dislocker` to use the
already existing RPM packages in Fedora could be a clever idea.

For RHEL-like (including CentOS Scientific Linux):

- `yum install gcc cmake make fuse-devel mbedtls-devel ruby-devel /usr/bin/ruby`

Alternatively, running `yum install dislocker fuse-dislocker` to use the
already existing RPM packages in EPEL could be a clever idea.

For FreeBSD:

- `pkg install cmake gmake fusefs-libs mbedtls`

For OSX: Follow the instructions in the next section.

Note that the code expects at least FUSE 2.6.

# INSTALLING

Each OS type has its own section below, beware to follow yours:

## If you are on MacOSX...

Just install Homebrew (http://brew.sh/) and run the following commands:
```
brew update
brew install Caskroom/cask/osxfuse
brew install src/dislocker.rb
```
This will install dislocker.


## If you're on FreeBSD...

Follow the instructions below (next subsection) by replacing 'make' with 'gmake'.

## If you are NOT on MacOSX...

If you already have installed the dependencies (see REQUIREMENTS section above),
you have to type the following commands to install the binaries on your system:
```
cmake .
make
sudo make install
```
Don't forget the dot (.) on the cmake command-line. If you only want to generate
the binaries, without installing them, you can skip the last command (the one
beginning with sudo).

Note that the '-Werror' flag in the cmake WARN_FLAGS variable may break the
compilation for useless warnings. If you know what you're doing, you can remove
it by running the following cmake command instead of the one above:
```
cmake -D WARN_FLAGS:STRING="-Wall -Wextra" .
```

See the [cmake documentation](http://www.cmake.org/documentation/) if you want
to customize the build.

Once installed, see `dislocker(1)` for details on how to use it.

# UNINSTALLING

I'm sure you don't want to do that. But if you're really forced by someone, just
type `make uninstall` as super-user.

# mbedTLS 2.0.0

Since the version 2.0.0 of mbedTLS, the build moves "crypto" functions such
as AES and SHA256 into a separate, libmbedcrypto, library. However, a typo
didn't installed this library, resulting in some packagers not providing this
library, thus breaking the dislocker compilation.
If you have this problem, it's recommended to run the following commands (they
have been put in the src/mbed_install.sh script, if you don't want to
copy/paste from here):
```
git clone https://github.com/ARMmbed/mbedtls.git
cd mbedtls
git checkout mbedtls-2.0.0
```
Then apply the patch given by the following command:
```
git show 6f42417b library/CMakeLists.txt
```
And compile/install the library:
```
cmake .
make
sudo make install
```

You can then resume the installation where you have left it.

# PORTABILITY

Globally, this was successfully tested on Linux x86/x86_64, MacOSX and FreeBSD.
It won't work on Windows and may not work on other BSDs (not tested).

For MacOSX, it has been tested against OSXFUSE 2.3.8 and 2.3.9.

Cases where you need to remove the '-Werror' from the WARN_FLAGS variable:

- You're on Ubuntu 10.04;
- You're using GCC with a version older than 4.3.


Whether it works or not, feel free to send comments and feedbacks to
[dislocker __AT__ hsc __DOT__ fr]().

# NOTE

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



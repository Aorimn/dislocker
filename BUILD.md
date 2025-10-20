# BUILDING NATIVE PACKAGES FOR DISLOCKER

This document provides instructions for building native system packages (e.g., `.deb` for Debian/Ubuntu, `.rpm` for Fedora/RHEL) from the `dislocker` source code.

For general compilation and installation, please see `README.md` and `INSTALL.md`.

## Building for Debian / Ubuntu 22.04 LTS

Ubuntu 22.04 LTS ships with **mbedTLS 2.28**, but the latest `dislocker` source code requires **mbedTLS 3.x**. The package for the new version has to be built before building dislocker.

This section provides the instructions based on a fesh install of [Ubuntu 22.04.5 LTS (Jammy Jellyfish)](https://releases.ubuntu.com/jammy/ubuntu-22.04.5-desktop-amd64.iso) 64-bit PC (AMD64) desktop image.

The commands can be executed in the default Terminal (GNOME Terminal).

### Building mbedTLS 3.x package

#### Update system and enable source repositories

```bash
sudo apt update
sudo apt -y full-upgrade
sudo add-apt-repository -y universe multiverse restricted
sudo sed -i -E 's/^# deb-src ([^#]+jammy[^#]*)/deb-src \1/' /etc/apt/sources.list
sudo apt update
```

#### Install all build tools and dependencies for mbedtls

```bash
sudo apt-get install -y \
  build-essential devscripts debhelper equivs ubuntu-dev-tools \
  fakeroot quilt lintian cmake pkg-config git ca-certificates \
  curl wget python3 python3-sphinx dh-python faketime doxygen graphviz
```

#### Set Maintainer Identity

Set this now to prevent warnings from uupdate and dch later.

```bash
export DEBFULLNAME="name"
export DEBEMAIL="name@email.org"
```

#### Download and Prepare Source Files

This fetches the Debian packaging files and the newer upstream source code.

Create a clean workspace, get Debian's 3.6.4 source package (for its 'debian' directory), and get the upstream 3.6.5 source tarball and rename it for uupdate

```bash
mkdir -p ~/build/mbedtls && cd ~/build/mbedtls
dget -ux https://deb.debian.org/debian/pool/main/m/mbedtls/mbedtls_3.6.4-2.dsc
wget https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2
mv mbedtls-3.6.5.tar.bz2 ../mbedtls_3.6.5.orig.tar.bz2
```

#### Merge New Source with Debian Packaging

Use uupdate to create the final source tree for building.

```bash
cd mbedtls-3.6.4
uupdate -v 3.6.5 ../mbedtls_3.6.5.orig.tar.bz2
cd ../mbedtls-3.6.5
```

#### Patch debian/control for Jammy Compatibility

This is the crucial step to fix the build errors. This safely removes the problematic lines.

Remove the dependency on dpkg-build-api, which is too new for Jammy, and relax the required version of dpkg-dev

```bash
sed -i '/dpkg-build-api/d' debian/control
sed -i -E 's/dpkg-dev \(>= 1\.22\.5\)/dpkg-dev/' debian/control
```

#### Finalize the Changelog

Create and finalize the changelog entry for your backport. You can use `dch -r` or `nano -l debian/changelog` for editing.

```bash
dch -D jammy "Backport Mbed TLS 3.6.5 for Jammy."
```

#### Build the Packages

This final step will compile everything and create the `.deb` files in the `~/build/mbedtls` directory.

```bash
debuild -b -us -uc
```

The list of 11 files that belong to the new final build are those named `*3.6.5-0ubuntu1*`:

1. The Installable Packages (.deb files). These are the most important files. They are the actual software packages you can install and share.

- libmbedcrypto16_3.6.5-0ubuntu1_amd64.deb
- libmbedtls21_3.6.5-0ubuntu1_amd64.deb
- libmbedx509-7_3.6.5-0ubuntu1_amd64.deb
- libmbedtls-dev_3.6.5-0ubuntu1_amd64.deb
- libmbedtls-doc_3.6.5-0ubuntu1_all.deb

2. The Debug Packages (.ddeb files). These are also part of the build output, but they are only for debugging purposes.

- libmbedcrypto16-dbgsym_3.6.5-0ubuntu1_amd64.ddeb
- libmbedtls21-dbgsym_3.6.5-0ubuntu1_amd64.ddeb
- libmbedx509-7-dbgsym_3.6.5-0ubuntu1_amd64.ddeb

3. Build Information and Logs. These files document how the packages were built. They are useful for reproducibility but are not installed.

- mbedtls_3.6.5-0ubuntu1_amd64.buildinfo
- mbedtls_3.6.5-0ubuntu1_amd64.changes
- mbedtls_3.6.5-0ubuntu1_amd64.build

#### Install the mbedTLS 3.x Packages

The `-dev` packages are requires to build `dislocker` later, but not to just use it. The `-doc` is just documentation.

```bash
cd ~/build/mbedtls
sudo apt install \
  ./libmbedcrypto16_3.6.5-0ubuntu1_amd64.deb \
  ./libmbedtls21_3.6.5-0ubuntu1_amd64.deb \
  ./libmbedtls-dev_3.6.5-0ubuntu1_amd64.deb \
  ./libmbedtls-doc_3.6.5-0ubuntu1_all.deb \
  ./libmbedx509-7_3.6.5-0ubuntu1_amd64.deb
```

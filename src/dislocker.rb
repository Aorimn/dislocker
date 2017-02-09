#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require 'formula'

class Dislocker < Formula
    homepage 'https://github.com/Aorimn/dislocker'
    url 'https://github.com/Aorimn/dislocker/archive/v0.7.zip'
    sha256 '807d7087e82b7ab5819a8ae1d5be6f074397c8f6a327b7b5798c1228e454424b'
    version '0.7.0'

    depends_on 'mbedtls'
    depends_on 'cmake'
#    This dependency is seperately installed, as a cask
#    depends_on :osxfuse

    def install
        system 'cmake', *std_cmake_args
        system 'make'
        system 'make', 'install'
    end
end

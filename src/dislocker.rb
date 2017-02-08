#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require 'formula'

class Dislocker < Formula
    homepage 'https://github.com/Aorimn/dislocker'
    url 'https://github.com/Aorimn/dislocker/archive/v0.7.zip'
    sha256 'ed5b0cb99de9fdbf7653f59e36bd31c84fdae2e40e13cefa688421cebb393cbd'
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

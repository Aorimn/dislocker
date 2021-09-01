#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require 'formula'

class Dislocker < Formula
    homepage 'https://github.com/Aorimn/dislocker'
    url 'https://github.com/Aorimn/dislocker/archive/v0.7.2.zip'
    sha256 '9c7cbc44193f560bbe4c23bc2568485d8a77a9f598c86ba41465cd0eb0cf4441'
    version '0.7.2'

    depends_on 'mbedtls'
    depends_on 'cmake'
#    This dependency is separately installed, as a cask
#    depends_on :osxfuse

    def install
        system 'cmake', *std_cmake_args
        system 'make'
        system 'make', 'install'
    end
end

#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require 'formula'

class Dislocker < Formula
    homepage 'https://github.com/Aorimn/dislocker'
    url 'https://github.com/Aorimn/dislocker/archive/v0.6.zip'
    sha256 '9738fdaa224de5669fe98dbd2a2edfbb1f2d0021e63045140d693c401e673ce4'
    version '0.6.0'

    depends_on 'polarssl'
    depends_on 'cmake'
    depends_on :osxfuse

    def install
        system 'cmake', *std_cmake_args
        system 'make'
        system 'make', 'install'
    end
end

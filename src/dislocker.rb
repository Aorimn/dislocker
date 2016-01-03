#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require 'formula'

class Dislocker < Formula
    homepage 'https://github.com/Aorimn/dislocker'
    url 'https://github.com/Aorimn/dislocker/archive/v0.5.zip'
    sha256 '20116021d6438c7551033f4a321bdc0659dba39227a9fd14c674f120cfd7c4aa'
    version '0.5.0'

    depends_on 'polarssl'
    depends_on 'cmake'
    depends_on :osxfuse

    def install
        system 'cmake', *std_cmake_args
        system 'make'
        system 'make', 'install'
    end
end

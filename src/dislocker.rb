#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require "formula"

class Dislocker < Formula
    homepage "https://github.com/Aorimn/dislocker"
    url "https://github.com/Aorimn/dislocker/archive/cd9d8e2e760fb94826e073112421442fdd287776.zip"
    sha256 "d319695711ae2bf0dbef67d686cf90081056ab1795671a4ea993d63035350d86"
    version "0.4.2"
    
    depends_on "polarssl"
    depends_on :osxfuse
    
    def install
        # This is a bit hackish, but is there another way?
        ssl_libname='mbedtls'
        if File.exists?("#{lib}/polarssl.a") && !File.exists?("/usr/local/Cellar/polarssl/1.3.10/mbedtls.a") # for some reason this returns false on my machine... I was fed up with it so I swapped the legacy support crap
            ssl_libname='polarssl'
        end
        
        system "make -C src SSLIB=#{ssl_libname}"
        system "make -C src install DESTDIR=#{prefix}/"
    end
end
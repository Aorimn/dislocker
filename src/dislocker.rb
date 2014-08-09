#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require "formula"

class Dislocker < Formula
  homepage "https://github.com/Aorimn/dislocker"
  url "https://github.com/Aorimn/dislocker/archive/master.zip"
  sha1 "f366f788d5a79c975e553f496ffd4eadc8427b2a"
  version "0.3.1"

  depends_on "polarssl"
  depends_on "osxfuse"

  def install
    system "make -C src fuse"
    system "make -C src install INSTALL_PATH=#{prefix}/ MAN_PATH=#{prefix}/"
  end
end

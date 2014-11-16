#
# this brew file *must* be called 'dislocker.rb' to match the Formula
#

require "formula"

class Dislocker < Formula
  homepage "https://github.com/Aorimn/dislocker"
  url "https://github.com/Aorimn/dislocker/archive/v0.4.tar.gz"
  sha1 "d05858bd9d5d5fc0f21fef3ed6fa32bea13be762"
  version "0.4.0"

  depends_on "polarssl"
  depends_on "osxfuse"

  def install
    system "make -C src"
    system "make -C src install DESTDIR=#{prefix}/"
  end
end

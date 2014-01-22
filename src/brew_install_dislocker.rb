require "formula"

class Dislocker < Formula
  homepage "https://github.com/Aorimn/dislocker"
  url "https://github.com/Aorimn/dislocker/archive/master.zip"
  sha1 "f366f788d5a79c975e553f496ffd4eadc8427b2a"
  version "0.3.1"

  depends_on "polarssl"
  depends_on "osxfuse"

  def install
    system "make"
    system "make install INSTALL_PATH=#{prefix}"
  end

  def do
    system "dislocker"
  end

end

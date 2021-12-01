#!/usr/bin/env ruby
#
# Dislocker -- enables to read/write on BitLocker encrypted partitions under
# Linux
# Copyright (C) 2012-2013  Romain Coltel, Hervé Schauer Consultants
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.
#

# $LOAD_PATH.unshift '@libdir@'
require '../libdislocker'


if ARGV.empty? or ARGV.length < 2
	puts "Usage: #{$0} <volume path> <user pass> [<offset> [<block>]]"
	exit 1
end

volume   = ARGV[0]
userpass = ARGV[1]
offset   = 0
block    = 0

if ARGV.length > 2
	offset = ARGV[2].to_i
end

if ARGV.length > 3
	block = ARGV[3]
end

dismeta = Dislocker::Metadata.new volume, offset, block

disaccess = Dislocker::Accesses.new(dismeta)
disaccess.vmk_from_userpass userpass

fvek = disaccess.fvek

puts ". FVEK found:"
puts fvek

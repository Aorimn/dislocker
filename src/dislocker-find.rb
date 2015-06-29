#!/usr/bin/env ruby

# This placeholder is replaced during `make' for the script to find libdislocker
# once installed
$LOAD_PATH.unshift '@SED_LIBDIR_PLACEHOLDER@'
require 'libdislocker'

$signatures = Dislocker::Signatures::BitLocker
$guids      = Dislocker::Metadata::GUID::INFORMATION_OFFSETS

def get_partitions
	uname = nil
	reps = %w(/bin/ /usr/bin/ /sbin/ /usr/sbin/)
	reps.each do |rep|
		uname = "#{rep}uname" if File.exists?("#{rep}uname")
	end

	if uname.nil?
		$stderr.puts 'Cannot find uname binary.'
		return []
	end

	os = `#{uname} -s`
	os.chomp!
	os.downcase!

	if Symbol.all_symbols.any? { |sym| sym.to_s == "get_#{os}_partitions" }
		return send "get_#{os}_partitions"
	else
		$stderr.puts 'OS not supported.'
	end

	return []
end

def get_freebsd_partitions
	return Dir['/dev/diskid/*']
end

def get_linux_partitions
	fd = File.open('/proc/partitions', 'r')
	lines = fd.readlines
	fd.close

	if lines.count <= 2
		$stderr.puts 'Wrong file format.'
		exit -1
	end

	# Remove header and empty line
	lines = lines.last(lines.count - 2)
	lines = lines.map do |line|
		line.split /\s+/
	end

	return lines.map do |line|
		"/dev/#{line[4]}"
	end
end

def get_darwin_partitions
	return Dir['/dev/disk*']
end

# Check if a device is BitLocker-encrypted
def is_bitlocker_encrypted?(device)
	begin
		fd = File.open(device, 'rb')
	rescue Errno::ENOMEDIUM
		# This doesn't concern us, it's for cdrom media
		return false
	rescue Errno::EBUSY
		# This means in OSX that the device is mounted, we can't figure if it's
		# a BitLocker partition or not
		return false
	end
	begin
		volume_header = fd.read_nonblock(512)
	rescue
		# If we can't read 512 bytes, then it's not a BitLocker volume
		return false
	else
		volume_signature = volume_header[3, 8]
	end
	fd.close

	$signatures.each do |sig|
		# First check is the volume's signature
		if sig == volume_signature
			$guids.each do |guid|
				# Second one is the volume's GUID
				return true if volume_header[guid]
			end
		end
	end

	return false
end



#
# Begin here
#
if ARGV.empty?
	devices = get_partitions
elsif ARGV[0] =~ /^--help|-h$/
	puts "Usage: #{$0} [-h] [files...]"
	puts '  Try to find partitions which are BitLocker-encrypted. Each found is'
	puts '   printed on stdout.'
	puts "  If one or more file is passed as argument, #{$0} will print each"
	puts '   file which is a BitLocker-encrypted volume.'
	puts '  The number of partition found is returned (in $? in sh).'
	exit 0
else
	devices = ARGV
end

encrypted_devices = []
devices.each do |dev|
	next unless File.exists? dev
	encrypted_devices << dev if is_bitlocker_encrypted? dev
end

if encrypted_devices.empty?
	$stderr.puts 'No BitLocker volume found.'
else
	puts encrypted_devices
end

exit encrypted_devices.count

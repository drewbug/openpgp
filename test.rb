#!/usr/bin/env ruby

require './openpgp'

def printsubpacket(sub)
	print "       # len #{sub.length}, #{sub.typename}: "
	case sub.type
	when SigV4SubPacket::PrefCompression
		sub.value.each do |i|
			print "#{CompressionAlgo.name(i)} "
		end
		puts
	when SigV4SubPacket::PrefHash
		sub.value.each do |i|
			print "#{HashAlgo.name(i)} "
		end
		puts
	when SigV4SubPacket::PrefSymmetric
		sub.value.each do |i|
			print "\"#{SymmetricAlgo.name(i)}\" "
		end
		puts
	when SigV4SubPacket::Issuer
		puts "0x#{sub.value.upcase}"
	when SigV4SubPacket::Flags, SigV4SubPacket::Features,
	     SigV4SubPacket::KeyServerOptions 
		sub.value.each do |n,v|
			print "#{n} "if v
		end
		puts
	else
		p sub.value
	end
end

ring = PacketComposition.fileread(if ARGV.empty? then 'testfile' else ARGV[0] end)
#if ring.armored
#	puts "Armor type: #{ring.armortype}"
#	print 'Armor header: '
#	p ring.armorheader
#end

ring.each_packet do |pkt,offset|
 begin
	pkt = pkt.inherit
	puts "#{offset}:: #{pkt.typename}, length #{pkt.length}"
	
	case pkt.ptype
	when Packet::PubKey, Packet::PubSubKey
		puts " -> version #{pkt.version}, algo #{pkt.algorithm} (#{PubKeyAlgo.name(pkt.algorithm)})"
		puts "    created #{pkt.ctime}"
		puts "    expires #{pkt.expires}" unless pkt.version4?
		puts " -> #{pkt.algvalues.join " "}"
		puts " -> fpr #{pkt.fingerprint}" if pkt.version4?
		puts " -> keyid #{pkt.keyid}" if pkt.version4?
	when Packet::SecKey, Packet::SecSubKey
		puts " -> version #{pkt.version}, algo #{pkt.algorithm} (#{PubKeyAlgo.name(pkt.algorithm)})"
		puts "    created #{pkt.ctime}"
		puts "    expires #{pkt.expires}" unless pkt.version4?
		puts " -> #{pkt.algvalues.join " "}"
		puts " -> s2k #{pkt.s2kval}"
	when Packet::UserId
		puts ' -> ' + pkt.uid
	when Packet::Attribute
		pkt.each_subpacket do |sub|
			sub = sub.inherit
			puts " -> subpacket #{sub.typename}, length #{sub.length}"
			puts "    #{sub.formatname}, length #{sub.imagelength}"
			#File.open('/tmp/ruby-openpgp.jpeg', 'w') do |f|
			#	f.write(sub.data)
			#end
		end
	when Packet::Trust
		puts " -> flag #{pkt.flag}, sigcache #{pkt.sigcache}"
	when Packet::Signature
		puts " -> version #{pkt.version}, type 0x#{pkt.sigtype.chr.unpack('H*')[0]},"
		puts "    pubk-algo #{pkt.pubkeyalgo} (#{PubKeyAlgo.name(pkt.pubkeyalgo)}), hashalgo #{pkt.hashalgo} (#{HashAlgo.name(pkt.hashalgo)})"
		pkt.algvalues.each do |n,v|
			puts "    -> #{n} = #{v}" if n != :algo
		end
		if pkt.version == 4
			puts "    -> hashed subpackets, length #{pkt.hashedsublength}"
			pkt.each_subpacket(true) do |sub|
				printsubpacket(sub)
			end
			puts "    -> unhashed subpackets, length #{pkt.sublength}"
			pkt.each_subpacket(false) do |sub|
				printsubpacket(sub)
			end
		else
			puts "    created #{pkt.ctime}, keyid 0x#{pkt.keyid}"
		end
		puts " -> lefthash 0x#{pkt.hash16.unpack('H*')[0]}"
	end
rescue RuntimeError => error
	puts "Error: #{error}   ...skipping"
	next
 end
end

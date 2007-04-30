# (C) Stephan Beyer <s-beyer@gmx.net>, 2005, GPL
# THIS IS NOT A FINAL RELEASE, JUST A PREVIEW, UPDATED IRREGULARLY.
# DON'T USE IT!
# MANY FUNCTIONS/CLASSES/MODULES ARE PROVISIONAL! I will not accept patches at this
# early state but you may send comments or questions about this project. The 
# design may (will!) change. Type system is inconsistent to see what solution
# fits best. Documentation will follow. (Inofficial) Debian packages will follow 
# when the first release is ready. 

# ATM This module only implements _read-only functions_ for handling OpenPGP
# data.
# OpenPGP is RFC2440 but there are also new internet drafts, see
#	http://www.ietf.org/ids.by.wg/openpgp.html

#### GAAAH! I just found `OpenPKSD' which is a keyserver written in Ruby.
#### I think this is a well-grown alternative to this code. http://www.openpksd.org/

# Vim users:
#	:set ts=4

# Current state:
#  - library and test program in this one file
#  - keys and keyrings (V2,V3,V4) can be read

# Versioning:
#  * this preview isn't a real version :) But it's some kind of the latest state.
#  * each release will be versioned by its release date
#  * releases will be classified in `primestones'
#    (mersenne prime milestone number), planned is:
#      - primestone 3: low-level functions for OpenPGP reading
#      - primestone 7: low-level read-write functions
#      - primestone 31: higher-level functions, documentation
#      - primestone 127: ...
#      - primestone 8191: equal to 127 but nobody will notice
#      - primestone 131071: encryption, decryption, verifying, signing
#      - primestone 524287: fetch your cat from a tree, make coffee
#      - primestone 2147483647: peace and world domination

require 'digest/sha1'

class String
	# str.end(3) returns a substring from position 3 to the end.
	# Like str[3..-1] but if empty, the result will be '' instead of nil
	def end(pos)
		ret = self[pos..-1]
		(ret.nil? ? '' : ret)
	end
end

# scalar: big-endian number of 2 or 4 octets, unsigned
# scalar() converts str into a scalar (Fixnum/Bignum)
def scalar(str)
	if str.is_a? Integer
		str
	else
		sl = str.length
		case sl
		when 0
			0
		when 1
			str[0]
		when 2
			(str[0]<<8)|str[1]
		when 4
			(str[0]<<24)|(str[1]<<16)|(str[2]<<8)|str[3]
		else # the following also works on the rest
			ret = 0
			str.each_byte do |b|
				sl -= 1
				ret |= b<<(sl*8)
			end
			ret
		end
	end	
end

# mpi: 2-octet scalar = length ; string containing big-endian number
# mpi() converts str into a number
# parameters: str = a string, offset = position offset where the MPI starts at
# return value: a list [0] is the number and [1] is the new position in str
#
# if mpi is only invoked with str and offset is unset, it will just return the
# value, not a new position
def mpi(str, offset=nil)
	pos = (offset.nil? ? 0 : offset)
	#$stderr.print "MPI: pos #{pos} "
	#$stderr.print scalar(str[pos,2])
	len = (scalar(str[pos,2]) / 8.0).ceil
	pos += 2
	#$stderr.print "\t\tlen #{len}\tnewpos #{pos+len}\n"
	ret = scalar(str[pos,len])
	if offset.nil?
		ret
	else
		[ret, pos+len]
	end
end

# generate a scalar string from an integer
# if pad is given, the string will be enlarged or shortened to length "pad"
def to_scalar(num, pad=0)
	str = ''
	while(num > 0)
		str = (num%256).chr + str
		num /= 256
	end
	if pad > 0
		if str.length < pad
			str = (0.chr)*(pad - str.length) + str
		elsif str.length > pad
			str = str[-pad,pad]
		end
	end
	str
end

# generate mpi from integer num
def to_mpi(num)
	n = to_scalar(num)
	l = (n.length-1)*8
	i = 0
	i += 1 while(n[0]>>i > 1)
	to_scalar(l+i+1,2) + n
end

# returns the length of a packet (new format with partial length)
# -- partial not yet tested!
def packetlength(str, partial, pos)
	if str[pos] < 192
		bodylen = str[pos]
		pos+=1
	elsif str[pos] < 224
		bodylen = ((str[pos] - 192) << 8) + str[pos+1] + 192
		pos+=2
	elsif str[pos] < 255
		bodylen = 1 << (str[pos] & 0b11111)
		partial = true
		pos+=1
	elsif not partial # indirect: and str[1] == 255
		bodylen = scalar(str[pos+1,4])
		pos+=5
	else
		raise 'ShouldNotBePossible -> Bug with partial!'
	end
	[bodylen, partial, pos]
end

# the same, but without partial length
def packetlength_without_partial(str, pos)
	if str[pos] < 192
		bodylen = str[pos]
		pos+=1
	elsif str[pos] < 255
		bodylen = ((str[pos] - 192) << 8) + str[pos+1] + 192
		pos+=2
	else # indirect: str[pos] == 255
		bodylen = scalar(str[pos+1,4])
		pos+=5
	end
	[bodylen, pos]
end

class KeyIdV3 < String
	def initialize(str)
		raise 'KeyId not 8 octets long' if str.length != 8
		super(str.unpack('H*')[0])
	end
end

class Packet
protected
	## maybe this should be a mix-in or something :)
	def algvalues(pos)
	end

public
	None, PubKeyEnc, Signature, SymKeyEnc, OnePassSig, SecKey, PubKey,
	SecSubKey, Compressed, Encrypted, Marker, Literal, Trust, UserId,
	PubSubKey = *0..14
	CommentOld, Attribute, EncryptedMDC, MDC = *16..19

	def typename
		case @ptype
			when None then 'Reserved'
			when PubKeyEnc then 'Public-Key Encrypted Session Key Packet' 
			when Signature then 'Signature Packet' 
			when SymKeyEnc then 'Symmetric-Key Encrypted Session Key Packet' 
			when OnePassSig then 'One-Pass Signature Packet' 
			when SecKey then 'Secret Key Packet' 
			when PubKey then 'Public Key Packet' 
			when SecSubKey then 'Secret Subkey Packet' 
			when Compressed then 'Compressed Data Packet' 
			when Encrypted then 'Symmetrically Encrypted Data Packet' 
			when Marker then 'Marker Packet' 
			when Literal then 'Literal Data Packet'
			when Trust then 'Trust Packet'
			when UserId then 'User ID Packet'
			when PubSubKey then 'Public Subkey Packet'
			when CommentOld then 'Old Comment Packet' 
			when Attribute then 'User Attribute Packet'
			when EncryptedMDC then 'Sym. Encrypted and Integrity Protected Data Packet'
			when MDC then 'Modification Detection Code Packet'
			else 'unknown'
		end
	end
	def typenameshort
	# TODO
		case @ptype
			when None then '***'
			when PubKeyEnc then '***' 
			when Signature then 'sig' 
			when SymKeyEnc then '***' 
			when OnePassSig then '***'
			when SecKey then 'sec'
			when PubKey then 'pub'
			when SecSubKey then 'ssb'
			when Compressed then '***'
			when Encrypted then '***'
			when Marker then 'mrk'
			when Literal then 'lit'
			when Trust then 'tru'
			when UserId then 'uid'
			when PubSubKey then 'sub'
			when CommentOld then '***'
			when Attribute then 'uat'
			when EncryptedMDC then '***'
			when MDC then 'mdc'
			else '***'
		end
	end

	attr_reader :ptype
	def initialize(data, type)
		@body = data
		@ptype = type
	end

	def inherit # TODO add all types
		case @ptype
		when UserId
			UserIdPacket.new(@body)
		when PubKey, PubSubKey, SecKey, SecSubKey
			PubKeyPacket.new(@body, @ptype)
		when Attribute
			UserAttributePacket.new(@body)
		when Signature
			SignaturePacket.new(@body)
		when Trust
			TrustPacket.new(@body)
		else
			self
		end
	end

	def length
		@body.length
	end
end

module PubKeyAlgo
	RSA = 1..3
	RSA_ES, RSA_E, RSA_S = *RSA # _E and _S are deprecated
	DSA, EC, ECDSA = *17..19
	Elgamal = [16, 20] # 20 (Elgamal Enc/Sign) isn't permitted to generate
	Elgamal_E, Elgamal_ES = *Elgamal
	DiffH = 21
	
	def PubKeyAlgo.name(type)
		case type
			when RSA_ES then 'RSA'
			when RSA_E then 'RSA (Encrypt)'
			when RSA_S then 'RSA (Sign)'
			when DSA then 'DSA'
			when EC then 'Elliptic Curve'
			when ECDSA then 'ECDSA'
			when Elgamal_ES then 'Elgamal'
			when Elgamal_E then 'Elgamal (Encrypt)'
			when DiffH then 'Diffie-Hellman (X9.42)'
		end
	end

end

module HashAlgo
	MD5, SHA1, RIPEMD160 = *1..3
	SHA256, SHA384, SHA512 = *8..10

	def HashAlgo.name(type)
		case type
			when MD5 then 'MD5'
			when SHA1 then 'SHA-1'
			when RIPEMD160 then 'RIPE-MD/160'
			when SHA256 then 'SHA256'
			when SHA384 then 'SHA384'
			when SHA512 then 'SHA512'
		end
	end
end

module SymmetricAlgo
	None, IDEA, TripleDS, CAST5, Blowfish = *0..4
	AES = 7..9
	AES128, AES192, AES256 = *AES
	Twofish = 10

	def SymmetricAlgo.name(type)
		case type
			when None then 'unencrypted data'
			when IDEA then 'IDEA'
			when TripleDS then 'TripleDES'
			when CAST5 then 'CAST5'
			when Blowfish then 'Blowfish'
			when AES128 then '128-bit AES'
			when AES192 then '192-bit AES'
			when AES256 then '256-bit AES'
			when Twofish then '256-bit Twofish'
		end
	end
end

module CompressionAlgo
	None, ZIP, ZLIB, BZ2 = *0..3
	def CompressionAlgo.name(type)
		case type
			when None then 'Uncompressed'
			when ZIP then 'ZIP'
			when ZLIB then 'ZLIB'
			when BZ2 then 'BZip2'
		end
	end
end

# check version and inherit to V3 or V4 packet
module SignaturePacket
	def algvalues_mixin(pos)
		begin
			case pubkeyalgo
			when PubKeyAlgo::RSA
				{ :algo => pubkeyalgo,
				  :s => mpi(@body.end(pos)) }
			when PubKeyAlgo::DSA
				r, pos = *mpi(@body, pos)
				{ :algo => pubkeyalgo,
				  :r => r,
				  :s => mpi(@body, pos)[0] }
			else # unknown algo
				{}
			end
		rescue
			raise "Broken algorithm values or bug!"
		end
	end

	def SignaturePacket.new(data)
		#print "SignaturePacket.new: "
		#p data.end(1).unpack('H*')
		case data[0]
		when 2
			SignatureV2Packet.new(data.end(1))
		when 3
			SignatureV3Packet.new(data.end(1))
		when 4
			SignatureV4Packet.new(data.end(1))
		else
			raise "Signature Version #{data[0]} != 2, 3 or 4 not supported!"
		end
	end
end

class SignatureV3Packet < Packet
	include SignaturePacket

	def initialize(data)
		raise 'SigV3Packet invalid!' if data[0] != 5
		super(data, Signature)
	end
	def version
		3
	end

	def sigtype
		@body[1]
	end

	def ctime
		Time.at(scalar(@body[2,4]))
	end

	def keyid
		KeyIdV3.new(@body[6,8])
	end

	def pubkeyalgo
		@body[14]
	end

	def hashalgo
		@body[15]
	end

	def hash16 # the left 16 bits of signed hash value
		@body[16,2] # TODO unpack them?
	end

	def algvalues
		algvalues_mixin(18)
	end
end

class SignatureV2Packet < SignatureV3Packet
	def version
		2
	end
end

class SignatureV4Packet < Packet
	include SignaturePacket

	def initialize(data)
		super(data, Signature)
	end
	def version
		4
	end

	def sigtype
		@body[0]
	end

	def pubkeyalgo
		@body[1]
	end

	def hashalgo
		@body[2]
	end

	# length of all hashed subpackets
	def hashedsublength
		scalar(@body[3,2])
	end

	# length of all unhashed subpackets
	def sublength
		scalar(@body[hashedsublength+5,2])
	end

	def each_subpacket(hashed) 
		pos = 5
		upto = 5+hashedsublength;
		unless hashed
			pos += hashedsublength+2
			upto = pos+sublength
		end
		while pos < upto
			len, pos = *packetlength_without_partial(@body, pos)
			type = @body[pos]
			# len includes `type octet' :\
			pos += 1
			yield SigV4SubPacket.new(@body[pos, len - 1], type)
			pos += len - 1
		end
	end

	def hash16 # the left 16 bits of signed hash value
		@body[7+hashedsublength+sublength,2] # TODO unpack them?
	end

	
	def algvalues
		algvalues_mixin(9+hashedsublength+sublength)
	end
end

class SigV4SubPacket
	Created, Expires, Exportable, Trust, RegExp, Revocable = *2..7
	KeyExpires, Placeholder, PrefSymmetric, RevKey = *9..12
	Issuer = 16
	Notation, PrefHash, PrefCompression, KeyServerOptions, PrefKeyServer,
	Primary, PolicyUrl, Flags, SignersUid, RevReason, Features,
	SigTarget, Embedded = *20..32

	def length ## REMOVE TODO
		@body.length
	end

	def initialize(data, type)
		@body = data ## REMOVE TODO
		@type = type
		@value = case type
		when Created, Expires, KeyExpires
			raise "Signature sub packet (#{typename})  is no timestamp!" if data.length != 4
			Time.at(scalar(data))
		when Exportable, Revocable, Primary
			raise "Signature sub packet (#{typename}) is no boolean!" if data.length != 1
			!data[0].zero?
		when Issuer
			KeyIdV3.new(data)
		when PrefSymmetric, PrefHash, PrefCompression
			data.unpack('c*')
		when PrefKeyServer, PolicyUrl, SignersUid, RegExp
			data   # return RegExp as String?? (TODO?)
		when Trust
			raise 'Invalid trust signature sub packet!' if data.length != 2
			{ :level => data[0], :amount => data[1] }
		when RevKey
			#raise 'Invalid revocation key sub packet!' if data.length != 22
			{ :sensitive => (data[0].zero? ? false : true),
			  :algorithm => data[1],
			  :fingerprint => data[2,20].unpack('H*') }
		when Notation
			raise 'Invalid notation data sub packet!' if data.length <= 8
			namelen = scalar(data[4,2])
			valuelen = scalar(data[6,2])
			{ :plaintext => !(data[0] & 0x80).zero?,
			  :name => data[8, namelen],
			  :value => data[8+namelen, valuelen] }
			# if the value is always quoted (in my tests it was), so
			# remove the quotes
		when KeyServerOptions
			{ :nomodify => !(data[0] & 0x80).zero? }
		when Flags
			{ :certkeys => !(data[0] & 1).zero?,
			  :signdata => !(data[0] & 0x2).zero?,
			  :enc_communication => !(data[0] & 0x4).zero?,
			  :enc_storage => !(data[0] & 0x8).zero?,
			  :secretsplit => !(data[0] & 0x10).zero?,
			  :auth => !(data[0] & 0x20).zero?,
			  :group => !(data[0] & 0x80).zero? }
		when Features
			{ :mdc => !(data[0] & 1).zero? }
		when SigTarget #untested
			{ :pubkeyalgo => data[0],
			  :hashalgo => data[1], 
			  :hash => data.end(2) }  # TODO unpack hash?
		when RevReason # untested
			{ :revocationcode => data[0],
			  :reason => data.end(1) }
		when Embedded #untested
			SignaturePacket.new(data)
		else # TODO
			:notyetimplemented
		end
	end
	attr_reader :value, :type

	def typename
		case @type
			when Created then 'creation time'
			when Expires then 'expiration time'
			when Exportable then 'exportable certification'
			when Trust then 'trust signature'
			when RegExp then 'regular expression'
			when Revocable then 'revocable'
			when KeyExpires then 'key expiration time'
			when Placeholder then 'placeholder for backward compatibility'
			when PrefSymmetric then 'preferred symmetric algorithms'
			when RevKey then 'revocation key'
			when Issuer then 'issuer key ID'
			when Notation then 'notation data'
			when PrefHash then 'preferred hash algorithms'
			when PrefCompression then 'preferred compression algorithms'
			when KeyServerOptions then 'key server preferences'
			when PrefKeyServer then 'preferred key server'
			when Primary then 'primary User ID'
			when PolicyUrl then 'policy URL'
			when Flags then 'key flags'
			when SignersUid then "signer's User ID"
			when RevReason then 'reason for revocation'
			when Features then 'features'
			when SigTarget then 'signature target'
			when Embedded then 'embedded signature'
			when 100..110 then 'internal or user-defined'
			else 'unknown'
		end
	end
end

class UserIdPacket < Packet
public
	def initialize(data)
		super(data, UserId)
	end

	def uid
		@body
	end

	def name
		@body.sub(/[ ]*[\(<].*$/, '').split.map do |word|
			word.capitalize
		end.join(' ')
		# this is stolen from `ksp-sign' but should we capitalize *here*?
	end

	def email
		@body.sub(/^.*<(.*@.*)>$/, '\1') if has_email?
	end

	def comment
		@body.sub(/^.*\((.*)\).*$/, '\1') if has_comment?
	end

	def has_comment?
		not (@body !~ /\(.*\)/)
	end

	def has_email?
		not (@body !~ /<.*@.*>$/)
	end

	# TODO uid=
	# TODO comment=
	# TODO email=
	# TODO name=
end

class UserAttributePacket < Packet
	def initialize(data)
		super(data, Attribute)
	end

	def each_subpacket 
		pos = 0
		partial = false

		while pos < @body.length
			len, partial, pos = *packetlength(@body, partial, pos)
			type = @body[pos]
			pos += 1
			yield UserAttributeSubPacket.new(@body[pos, len], type)
			pos += len
		end
	end
end

class UserAttributeSubPacket
	Image = 1
	def typename
		case @ptype
			when Image then 'Photo'
			else 'unknown'
		end
	end
	
	def initialize(data, type)
		@body = data;
		@ptype = type;
	end

	def length
		@body.length
	end

	def inherit
		case @ptype
		when Image
			UserAttributeSubPacketImage.new(@body)
		else
			self
		end
	end
	attr_reader :ptype
end

# subclass of class UserAttributeSubPacket? (TODO)
class UserAttributeSubPacketImage < UserAttributeSubPacket
	JPEG = 1
	def formatname
		case @format
			when JPEG then 'JPEG'
			else 'unknown'
		end
	end

	def hdrlen
		@body[0]|(@body[1]<<8)
	end
	
	def initialize(data)
		super(data, Image)
		@hdrversion = data[2]
		# hdrversion = 1 -> hdrlen = 16
		
		case @hdrversion
		when 1
			@format = data[3]
			@data = data.end(hdrlen) # this is the image data itself
		else
			raise 'Image Header Version != 1 not supported!'
		end
	end

	attr_reader :hdrversion, :format, :data

	def imagelength
		@data.length
	end
end

# a TrustPacket is implementation-dependant.
class TrustPacket < Packet
	def initialize(data)
		super(data, Trust)
		if data.length == 2
			# treated as GnuPG trust packet
			@flag = data[0]
			@sigcache = data[1]
		else
			# not implemented
			@flag = nil
			@sigcache = nil
		end
	end
	attr_reader :flag, :sigcache
end

# the PubKeyPacket class provides functions for the similar packets:
# Public Key, Secret Key, Public Subkey, Secret Subkey
class PubKeyPacket < Packet
	def initialize(data, type=PubKey)
		super(data, type)
	end

	# checks if version is supported
	def version
		raise 'Invalid packet version!' unless @body[0].between?(2,4)
		@body[0]
	end

	# two predicate versions, not checking for values \notin {2,3,4}
	def version2?
		@body[0] == 2
	end
	def version3?
		@body[0] == 3
	end
	def version4?
		@body[0] == 4
	end

	# creation time
	def ctime
		Time.at(scalar(@body[1,4]))
	end
	def ctimestamp_bytes
		@body[1,4]
	end

	def expires
		case version
		when 4
			0 # public keys don't expire?
		when 2, 3
			Time.at(ctime+86400*scalar(@body[5,2]))
		end
	end

	def algorithm
		case version
		when 4
			@body[5]
		when 2, 3
			@body[7]
		end
	end

	def algvalues
		offset = 6
		offset += 2 if version3? or version2?
		
		case algorithm
		# TODO return Structs/Classes/Hashes, not Arrays
		# -> an Algorithm meta class. RSA, DSA, Elgamal classes derive from Algorithm
		when *PubKeyAlgo::RSA
			modulus, offset = *mpi(@body, offset)
			exponent = mpi(@body, offset)[0]
			###exponent = mpi(@body.end(offset)) is another variant
			[:rsa, modulus, exponent]
		when PubKeyAlgo::DSA
			prime, offset = *mpi(@body, offset)
			groupord, offset = *mpi(@body, offset)
			groupgen, offset = *mpi(@body, offset)
			value = mpi(@body, offset)[0]
			[:dsa, prime, groupord, groupgen, value]
		when *PubKeyAlgo::Elgamal
			prime, offset = *mpi(@body, offset)
			groupgen, offset = *mpi(@body, offset)
			value = mpi(@body, offset)[0]
			[:elgamal, prime, groupgen, value]
		else
			[:unknown]
		end
		# FIXME 20070423 - why are there *s? ;-)
	end

	def fingerprint
		#a.1) 0x99 (1 octet)
		#a.2) high order length octet of (b)-(f) (1 octet)
		#a.3) low order length octet of (b)-(f) (1 octet)
		#b) version number = 4 (1 octet);
		#c) time stamp of key creation (4 octets);
		#d) algorithm (1 octet): 17 = DSA (example);
		#e) Algorithm specific fields.
		#   Algorithm Specific Fields for DSA keys (example):
		#e.1) MPI of DSA prime p;
		#e.2) MPI of DSA group order q (q is a prime divisor of p-1);
		#e.3) MPI of DSA group generator g;
		#e.4) MPI of DSA public key value y (= g**x mod p where x is secret).
		if version == 4
			fprbody = 0x04.chr + ctimestamp_bytes + algorithm.chr
			case algorithm
			when PubKeyAlgo::RSA
				(_,mod,exp) = algvalues
				fprbody << to_mpi(mod) + to_mpi(exp)
			when PubKeyAlgo::DSA
				(_,prime,ord,gen,val) = algvalues
				fprbody << to_mpi(prime) +
					to_mpi(ord) +
					to_mpi(gen) +
					to_mpi(val)
			when PubKeyAlgo::Elgamal, PubKeyAlgo::Elgamal_E, PubKeyAlgo::Elgamal_ES
				(_,prime,gen,val) = algvalues
				fprbody << to_mpi(prime) +
					to_mpi(gen) +
					to_mpi(val)
			else
				raise :notimplemented
			end
			x = to_scalar(fprbody.length) ### X1
			Digest::SHA1.hexdigest(
				0x99.chr +  ### a.1
				x[0,1] + x[-1,1] + ### X1 #to_scalar(fprbody.length, 2) + ### X2  ### a.2 and a.3
				### X1 and X2 are equivalent if keys are limited to 64k
				### FIXME s. Mail
				fprbody); ### (b)-(f)
		else
			:notimplemented_onlyV4
		end
	end

	def keyid(long=false)
		if long
			fingerprint[-16,16]
		else
			fingerprint[-8,8]
		end
	end
end

class PubSubKeyPacket < PubKeyPacket
	def initialize(data)
		super(data, PubSubKey)
	end
end

class SecKeyPacket < PubKeyPacket
	def initialize(data)
		super(data, SecKey)
	end
end

class SecSubKeyPacket < PubKeyPacket
	def initialize(data)
		super(data, SecSubKey)
	end
end

module Armor
	def Armor.crc24(str)
		crc = 0xb704ce
		str.each_byte do |b|
			#printf "#{crc} "
			crc ^= b<<16
			8.times do
				crc <<= 1
				crc ^= 0x1864cfb unless (crc & 0x1000000).zero?
			end
		end
		crc & 0xffffff
	end

	def Armor.base64(str)
		[str].pack('m')
	end

	def Armor.debase64(str)
		str.gsub(/[^A-Za-z0-9\+\/=]/, '').unpack('m')[0]
		# non base64 characters (except \n) will break unpack, so
		# they're removed without any warning.
		# They shouldn't be there anyway :)
	end

	def Armor.header(str)
		ret = {}
		str.each_line do |line|
			t = line.chomp.split(/: /)
			break unless t.length == 2
			ret.store(*t)
			# NOTE: if one header key is defined more than once
			# the key is overwritten in the hash. Is it useful
			# to append the new value string to the old string?
		end unless str.nil?
		ret
	end

	# return value:
	# if not armored: nil
	# if armored:
	#	[typestring, headerhash, binarydatastring, checksumstring (3 chars)] 
	def Armor.dearmor(str)
		m = %r|^-----BEGIN PGP (.*)-----$[\n\r]+(?:^(.*: [^\n\r]*[\n\r]+)*$[\n\r]+)?^(.*)=([/+\d\w]{4})$[\n\r]+^-----END PGP \1-----$|m.match(str)
		(m.nil? ? nil : [m[1], header(m[2]), debase64(m[3]), debase64(m[4])])
	end

	def Armor.armor(str)
		# TODO
	end
end

class PacketComposition
public
	def initialize(data)
		# FIXME only look for *one* armor -- TODO: check for more

		check = Armor.dearmor(data)
		@armored = !check.nil?
		if @armored
			@armortype, @armorheader, @ring = *check[0,3] 
		else
			@armored = false
			@armorheader = {}
			@armortype = ''
			@ring = data
		end
	end
	attr_accessor :armored, :armorheader, :armortype

	def PacketComposition.fileread(filename)
		ring = File.read(filename)
		self.new(ring)
	end
	
	
#	def change_packets #TODO later, first we handle read only
#		each_packet(false) do |pkt|
#			yield pkt
#		end
#	end

	def each_packet(readonly=true)
		pos=0
		partial=false # partial stuff not yet tested!

		while pos < @ring.length # used @ring for debugging only
			if (@ring[pos] >> 7).nonzero? # aka is_pkthdr (packet header)
				bodylen = 0
				
				if ((@ring[pos] >> 6) & 1).zero? # aka is_old_ring_format?
					partial=false
					type = (@ring[pos] & 0b111100) >> 2
					lengthtype = (@ring[pos] & 0b11)
					if lengthtype < 3
						(1 << lengthtype).downto(1) do |len|
							pos += 1
							bodylen <<= 8
							bodylen |= @ring[pos] 
						end
					else
						raise 'OpenPGP Old ring format Length Type 3 not supported!'
					end
					pos+=1
				else
					type=@ring[pos] & 0b111111
					bodylen, partial, pos = *packetlength(@ring, partial, pos+1)
				end
			else
				raise 'Invalid packet!'
			end

			ret = yield Packet.new(@ring[pos,bodylen], type), pos
#			unless readonly
#				@ring[pos,bodylen] = ret
#				# TODO
#				# header aender! ;)
#			end

			# TODO nicht bei partial yielden -- ?

			pos += bodylen
		end
	end
end

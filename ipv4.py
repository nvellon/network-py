from struct import unpack

HEADER_OFFSET = 14
HEADER_SIZE = 20

def decode_address (s):
	addr = "%.d.%.d.%.d.%.d" % (ord(s[0]), ord(s[1]), ord(s[2]), ord(s[3]))
	return addr

def decode_total_length (s):
	length = unpack('!H', s)
	return length[0]

def decode_ttl (s):
	ttl = '%.d' % ord(s)
	return ttl

def decode_protocol (s):
	proto = '%.d' % ord(s)
	return proto

# Obtiene el encabezado IPV4
def parse_header (packet, human = True):
	header = packet[HEADER_OFFSET:HEADER_OFFSET+HEADER_SIZE]

	ipv4 = unpack('!ss2s2s2sss2s4s4s', header)

	version = 0
	ihl = 0
	dscp = 0
	ecn = 0
	total_length = ipv4[2]
	identification = 0
	flags = 0
	fragment_offset = 0
	time_to_live = ipv4[5]
	protocol = ipv4[6]
	header_checksum = 0
	source_ip_address = ipv4[8]
	destination_ip_address = ipv4[9]

	if human:
		return [version, ihl, dscp, ecn, decode_total_length(total_length), identification, flags, fragment_offset, decode_ttl(time_to_live), decode_protocol(protocol), header_checksum, decode_address(source_ip_address), decode_address(destination_ip_address)]
	else:
		return [version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, time_to_live, protocol, header_checksum, source_ip_address, destination_ip_address]
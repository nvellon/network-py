from struct import unpack

# Ethernet en bytes/octetos
HEADER_OFFSET = 0
HEADER_SIZE = 14

# Internet Protocol version 4 (IPv4)
ETH_TYPE_IPV4 = '0x0800'

# Obtiene una direccion MAC desde una cadena de 6 bytes
def decode_address (a):
	addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
	return addr


# Obtiene el tipo de protocolo Ethernet desde una cadena de 2 bytes
def decode_type (t):
	type = "0x%.2x%.2x" % (ord(t[0]), ord(t[1]))
	return type


# Obtiene el encabezado Ethernet
def parse_header (packet, human = True):
	header = packet[HEADER_OFFSET:HEADER_OFFSET+HEADER_SIZE]

	destination, source, protocol_type = unpack('!6s6s2s', header)

	if human:
		return [decode_address(destination), decode_address(source), decode_type(protocol_type)]
	else:
		return [destination, source, protocol_type]
from struct import unpack

HEADER_OFFSET = 34
HEADER_SIZE = 16

def decode_port (s):
	port = unpack('!H', s)
	return port[0]

# Obtiene el encabezado TCP
def parse_header (packet, human = True):
	header = packet[HEADER_OFFSET:HEADER_OFFSET+HEADER_SIZE]
	data = packet[HEADER_OFFSET+HEADER_SIZE:65565]

	tcp = unpack('!2s2s4s4s4s', header)

	source_port = tcp[0]
	destination_port = tcp[1]
	sequence = tcp[2]
	acknowledgement = tcp[3]

	if human:
		return [decode_port(source_port), decode_port(destination_port), sequence, acknowledgement, data]
	else:
		return [source_port, destination_port, sequence, acknowledgement, data]
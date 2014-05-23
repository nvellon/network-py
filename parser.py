import socket
from struct import *

# Convierte una cadena de 6 caracteres a una direccion de seis hexadecimales separados por punto
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
	return b

def eth_type (a):
	b = "0x%.2x%.2x" % (ord(a[0]), ord(a[1]))
	return b

# Abro socket local
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# Recibe las tramas
while True:
	packet = s.recvfrom(65565)
	packet = packet[0]

	eth_dst_len = 6
	eth_src_len = 6
	eth_pro_len = 2
	
	eth_dst = packet[:eth_dst_len]
	eth_src = packet[eth_dst_len:eth_dst_len + eth_src_len]
	eth_pro = packet[eth_dst_len + eth_src_len:eth_dst_len + eth_src_len + eth_pro_len]
	
	print 'MAC Dst:  ' + eth_addr(eth_dst)
	print 'MAC Src:  ' + eth_addr(eth_src)
	print 'Eth Type: ' + eth_type(eth_pro)
	print
	print str(packet)
	print '====================================================================================='
	print

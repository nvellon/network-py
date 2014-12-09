import socket
import ethernet
import ipv4
import tcp
from struct import unpack

# Abro socket local
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# Recibe las tramas
while True:
	packet = s.recvfrom(65565)
	packet = packet[0]

	eth_header = ethernet.parse_header(packet)

	if eth_header[1] != 'a0:d3:c1:16:f0:a9':
		continue

	if ethernet.ETH_TYPE_IPV4 != eth_header[2]:
		continue

	ip_header = ipv4.parse_header(packet)

	if str(ip_header[9]) != '6':
		continue

	tcp_header = tcp.parse_header(packet)

	if str(tcp_header[1]) != '80':
		continue

	if len(tcp_header[4]) < 150:
		continue

	print 'ETHERNET HEADER'
	print '  MAC Destination: ' + eth_header[0]
	print '  MAC Source:      ' + eth_header[1]
	print '  Protocol Type:   ' + eth_header[2]
	print

	print '  IPV4 HEADER'
	print '    Total length:   ' + str(ip_header[4])
	print '    Identification: ' + str(ip_header[5])
	print '    Time to Live:   ' + str(ip_header[8])
	print '    Protocol:       ' + str(ip_header[9])
	print '    Source IP:      ' + ip_header[11]
	print '    Destination IP: ' + ip_header[12]
	print

	print '    TCP HEADER'
	print '      Source Port:      ' + str(tcp_header[0])
	print '      Destination Port: ' + str(tcp_header[1])
	print '      DATA:             ' + str(len(tcp_header[4]))
	print '      DATA:             ' + str(tcp_header[4])

	print '====================================================================================='
	print

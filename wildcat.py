#!/usr/bin/python

# Wildcat - Netcat All The Things!
# Written by psmitty7373
# Twitter - @psmitty7373
# Github - https://github.com/psmitty7373/wildcat

import argparse, random, re, select, socket, struct, subprocess, sys, threading, time, zlib
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read
from threading import Thread
from Queue import Queue

HEART_BEAT_TIME = 5000
RETRANSMIT_TIME = 1000
NETWORK_TIMEOUT = 30000
MAX_PACKET_SIZE = 500
DNS_LABEL_LEN = 63
DNS_MAX_QUESTIONS = 1

SYN = 0
ACK = 1
SACK = 2
PSH = 3
FIN = 4
HB = 5
BEGSTREAM = 6
ENDSTREAM = 7

IDLE = 0
GOT_SYN = 1
WAIT_ACK = 2
WAIT_HB = 3
GOT_HB = 4

COMPRESS = 1
DECOMPRESS = 2

#sysctl -w net.ipv4.icmp_echo_ignore_all=1

class ipserverThread(threading.Thread):
	def __init__(self, ip, port, proto, remote, opts):
		threading.Thread.__init__(self)
		self.oq = Queue(maxsize=0)
		self.oqlocked = False
		self.ip = ip
		self.port = port
		self.proto = proto
		self.server = False
		self.remoteid = None
		self.remote = remote
		self.opts = opts.split(',')
		self.running = True
		self.error = False
		self.done = False
		self.ready = False
		self.s = None
		self.c = None
		self.addr = None
		self.input = None
		self.stateful = False
		self.state = None
		self.compress = None
		self.lseq = 0
		self.rseq = 0
		self.lasthb = 0
		self.lastq = None
		self.lastid = None
		self.dnsname = None
		if remote == '':
			self.server = True
			self.id = random.randint(128,255)
		else:
			self.id = random.randint(0,128)
		if len(self.opts) > 0 and self.opts[0] != '':
			for i in self.opts:
				if i == 'r':
					self.stateful = True
				elif i == 'c':
					self.compress = COMPRESS
				elif i == 'd':
					self.compress = DECOMPRESS
				elif i[0:4] == 'dns=' and self.proto == 'dns':
					i = i.split('=')
					if len(i) == 2:
						i = i[1].split('.')
						if len(i) == 2:
							self.dnsname = i
						else:
							sys.stderr.write('[!] Error! A dns=<dns.name> option is required for the DNS protocol.\n')
							self.error = True
					else:
						sys.stderr.write('[!] Error! A dns=<dns.name> option is required for the DNS protocol.\n')
						self.error = True
				else:
					sys.stderr.write('[!] Error! Invalid option >>>' + i + '<<<\n')
					self.error = True
		if self.proto == 'dns' and self.dnsname == None:
			sys.stderr.write('[!] Error! A dns=<dns.name> option is required for the DNS protocol.\n')
			self.error = True
		self.recvthread = threading.Thread(target=self.recv)
		self.recvthread.daemon = True

	def openSocket(self):
		try:
			if self.proto == 'tcp':
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			elif self.proto == 'udp' or self.proto == 'dns':
				self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
			elif self.proto == 'icmp':
				self.s = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.getprotobyname('icmp'))
				self.s.bind((self.ip,0))
			else:
				return False
			if not self.proto == 'icmp' and self.server:
				self.s.bind((self.ip,int(self.port)))
			if self.proto == 'tcp' and self.server:
				self.s.listen(1)
			elif self.proto == 'tcp':
				sys.stderr.write('[*] Connecting to ' + self.remote[0] + ' on ' + self.proto + ' ' + str(self.remote[1]) + '.\n')
				self.s.connect(self.remote)
				self.ready = True
		except:
			sys.stderr.write('[!] Unable to open socket.\n')
			return False
		if self.server:
			sys.stderr.write('[*] Listening on port ' + str(self.port) + '\n')

		return True

	def icmp_cksum(self, msg):
		sum = 0
		count_to = (len(msg) / 2) * 2
		count = 0
		while count < count_to:
			i = ord(msg[count + 1])*256+ord(msg[count])
			sum = sum + i
			sum = sum & 0xffffffff
			count = count + 2
		if count_to < len(msg):
			sum = sum + ord(msg[len(msg) - 1])
			sum = sum & 0xffffffff
		sum = (sum >> 16) + (sum & 0xffff)
		sum = sum + (sum >> 16)
		cksum = ~sum
		cksum = cksum & 0xffff
		cksum = cksum >> 8 | (cksum << 8 & 0xff00)
		return cksum

	def dns_make(self, msg):
		id = 0
		if not self.server:
			id = 0x1337
		else:
			id = self.lastid
		bits = 0x0100
		qcount = 1
		acount = 0
		if self.server:
			bits = 0x8180
			acount = 1 
		msg = msg.encode('base64').replace('=','-').strip()
		n = 126
		msgs = [msg[i:i+n] for i in range(0, len(msg), n)]
		qcount = len(msgs)
		binq = ''
		bina = ''
		if not self.server:
			for i in msgs:
				labels = []
				if len(msg) > 63:
					a,b = i[:len(i)/2],i[len(i)/2:]
					labels = [a,b,'chaumurky','com']
				else:
					labels = [i,'chaumurky','com']
				for label in labels:
					binq += struct.pack('B', len(label))
					binq += label
				binq += '\0'
				binq += struct.pack('!HH', 16, 1)
		else:
			binq  = ''.join(self.lastq)
			name = 49164
			type = 16
			qcount = len(self.lastq)
			cls = 1
			ttl = 1
			dlen = len(msg) + 1
			tlen = len(msg)
			bina = struct.pack('!HHHIHB',name, type, cls, ttl, dlen, tlen)
			bina += msg
		binpckt = struct.pack('!HHHHHH', id, bits, qcount, acount, 0, 0)
		binpckt += binq + bina
		
		return binpckt

	def icmp_make(self, msg, type):
		if not self.server:
			id = random.randint(0,65535)
		else:
			id = self.lastid
		header = struct.pack('bbHHh', type, 0, 0, id, 1)
		cksum = self.icmp_cksum(header + msg)
		header = struct.pack('bbHHh', type, 0, socket.htons(cksum), id, 1)
		return header + msg

	def send(self, msg, flag=PSH, seq=-1, type=8):
		if self.proto == 'icmp' or self.proto == 'udp' or self.proto == 'dns':
			if self.compress == COMPRESS and msg != '':
				msg = zlib.compress(msg)
			n = MAX_PACKET_SIZE
			if self.proto == 'dns':
				n = 90
			msgs = [msg[i:i+n] for i in range(0, len(msg), n)]
			if len(msgs) == 0:
				msgs.append('')
			if self.stateful:
				if flag == PSH or flag == BEGSTREAM or flag == ENDSTREAM:
					if not self.server or self.proto == 'udp':
						self.state = WAIT_ACK
					else:
						self.state = WAIT_HB
						type = 0
			if self.compress == COMPRESS and flag == PSH and len(msgs) > 1:
				size = struct.pack('!I',len(msg))
				self.send('', BEGSTREAM, 0)
			for i in msgs:
				if self.stateful:
					if flag != ACK:
						seq = self.lseq;
					successful = False
					while not successful:
						curr_time = int(round(time.time() * 1000))
						i = chr(self.id) + chr(flag) + chr(seq) + i
						while self.state == WAIT_HB:
							time.sleep(0.01)
							timeout = int(round(time.time() * 1000))
							if curr_time - timeout > NETWORK_TIMEOUT:
								sys.stderr.write('[!] Connection timed out!\n')
								self.error = True
								return False
						if self.proto == 'icmp':
							packet = self.icmp_make(i, type)
						elif self.proto == 'dns':
							packet = self.dns_make(i)
						else:
							packet = i
						try:
							self.s.sendto(packet, (self.remote))
						except:
							sys.stderr.write('[!] Error! Unable to send packet.\n')
							self.error = True
							break
						# Retransmission timer / WAIT_ACK handler
						if flag != ACK:
							self.state = WAIT_ACK
							start_time = int(round(time.time() * 1000))
							timeout = int(round(time.time() * 1000))
							while (self.state == WAIT_ACK) and self.running:
								time.sleep(0.0001)
								curr_time = int(round(time.time() * 1000))
								if curr_time - timeout > NETWORK_TIMEOUT:
									sys.stderr.write('[!] Connection timed out!\n')
									self.error = True
									return False
								if curr_time - start_time > RETRANSMIT_TIME:
									if self.server:
										self.state = WAIT_HB
										continue
									try:
										self.s.sendto(packet, (self.remote))
									except:	
										print 'ERROR2'
										pass
										#TODO send error handling
									start_time = int(round(time.time() * 1000))
						successful = True
						if flag == PSH:
							self.lseq += 1
							if self.lseq > 254:
								self.lseq = 0
				else:
					if self.proto == 'icmp':
						packet = self.icmp_make(i, type)
					elif self.proto == 'dns':
						packet = self.dns_make(i)
					else:
						packet = i
					try:
						self.s.sendto(packet, (self.remote))
					except:	
						pass
						#TODO send error handling
			if self.compress == COMPRESS and flag == PSH and len(msgs) > 1:
				self.send('', ENDSTREAM, 0)
		else:
			try:
				self.c.sendall(msg)
			except:
				print 'ERROR3'
				pass
				#TODO send error handling

	def recv(self):
		while self.running and not self.error:
			if not self.ready and self.proto == 'tcp' and self.server:
				inp, outp, excpt = select.select([self.s],[],[],0)
				for x in inp:
					if x == self.s:
						try:
							self.c, self.addr = self.s.accept()
							self.ready = True
							self.input = [self.c]
							self.c.setblocking(0)
							sys.stderr.write('[*] Connection from ' + str(self.addr[0]) + '\n')
						except:
							sys.stderr.write('[!] Connection error.\n')
							self.error = True
							self.running = False
			else:
				if self.input != None:	
					inp, outp, excpt = select.select(self.input,[],[],0)
					while inp:
						if self.proto == 'udp' or self.proto == 'icmp' or self.proto == 'dns':
							data, addr = self.s.recvfrom(16384)
							if self.remote == '' or (self.proto == 'dns' and self.server):
								self.remote = addr
							if self.proto == 'icmp':
								icmp_hdr = data[20:28]
								type, code, chksum, id, seq = struct.unpack('bbHHh', icmp_hdr)
								if self.server:
									self.lastid = id
								data = data[28:]
							elif self.proto == 'dns' and len(data) > 20:
								dns_hdr = data[0:12]
								id, bits, qcount, acount, ncount, rcount = struct.unpack('!HHHHHH', dns_hdr)
								self.lastid = id
								data = data[12:]
								questions = []
								labels = []
								for i in range(qcount):
									nullbyte = data.find('\0')
									questions.append(data[0:nullbyte+5])
									while data[0] != '\0':
										qlen, = struct.unpack('!B', data[0])
										label, = struct.unpack('!%ds' % qlen, data[1:qlen+1])
										labels.append(label)
										data = data[qlen+1:]
									type, cls = struct.unpack('!HH',data[1:5])
									data = data[5:]
									del labels[-2:]
								self.lastq = questions
								for i in range(acount):
									name, type, cls, ttl, dlen, tlen = struct.unpack('!HHHIHB', data[:13])
									data = data[13:]
								if acount == 0:
									data = ''
									for i in labels:
										data += i
								try:
									data = data.replace('-','=').decode('base64')
								except:
									sys.stderr.write('[!] Erroneous base64 packet.\n')
									sys.stderr.write('>>>' + str(i) + '<<<\n')
									self.error = True
									continue

							if self.stateful and len(data) > 2:
								sid = ord(data[0])
								flag = ord(data[1])
								seq = ord(data[2])
								data = data[3:]
								#sys.stderr.write('M:' + str(sid) + ' F:' + str(flag) + ' RRS:' + str(seq) + ' TRS:' + str(self.rseq) + ' LS:' + str(self.lseq) + ' D:' + data + '\n')
								if sid != self.id:
									self.lasthb = int(round(time.time() * 1000))
									if flag == SYN and seq == 0 and data == '' and not self.ready:
										self.remote = addr
										self.state = GOT_SYN
										self.remoteid = sid
									elif flag == SACK and seq == 0 and data == '' and not self.ready:
										if self.state == WAIT_ACK and seq == self.lseq:
											self.state = IDLE
											self.ready = True
											self.remoteid = sid
											self.send('', ACK, 0, 8)
											sys.stderr.write('[*] Connection to ' + self.remote[0] + ' established.\n')
									elif sid == self.remoteid:
										if flag == ACK:
											if seq == self.lseq:
												if self.state == WAIT_ACK:
													self.state = IDLE
													if not self.ready:
														self.ready = True
														sys.stderr.write('[*] Connection from ' + addr[0] + '\n')
											elif seq < self.lseq:
												data = ''
												print 'OUT OF SYNC'
											else:
												print 'something crazy'
										elif flag == PSH:
											if seq == self.rseq:
												self.send('', ACK, seq, 0)
												self.rseq += 1
											elif seq < self.rseq:
												self.send('', ACK, seq, 0)
												data = ''
											else:
												print 'Packets from da future?!'
												#TODO Request old packet again... semething has happened
										elif flag == BEGSTREAM:
											self.oqlocked = True
											self.send('', ACK, seq, 0)
										elif flag == ENDSTREAM:
											self.oqlocked = False
											self.send('', ACK, seq, 0)
										elif flag == FIN:
											sys.stderr.write('[*] Connection from ' + addr[0] + ' closed.\n')
											self.error = True
											self.send('', ACK, seq, 0)
										elif flag == HB:
											if self.state != WAIT_HB:
												self.send('', ACK, seq, 0)
											else:
												self.state = GOT_HB
										if self.rseq > 254:
											self.rseq = 0
								else:
									data = ''
						elif self.proto == 'tcp':
							try:
								data = self.c.recv(16384)
							except:
								self.error = True
								sys.stderr.write('[!] Error! Recieve error.\n')
								break
						if self.proto == 'tcp' and len(data) == 0:
							if self.server:
								sys.stderr.write('[!] Connection from ' + self.addr[0] + ' lost.\n')
							else:
								sys.stderr.write('[!] Connection to ' + self.remote[0] + ' lost.\n')
							self.error = True
							break
						else:
							if data != '':
								self.oq.put(data)
						inp, outp, excpt = select.select(self.input,[],[],0)
			time.sleep(0.01)

	def run(self):
		if (self.proto == 'udp' or self.proto == 'icmp' or self.proto == 'dns') and not self.stateful:
			self.ready = True
		if not self.openSocket():
			self.error = True
		else:
			self.input = [self.s]
			self.c = self.s
			self.recvthread.start()
		while self.running:
			if not self.error:
				if not self.ready and (self.proto == 'icmp' or self.proto == 'udp' or self.proto == 'dns') and self.stateful:
					if not self.server:
						if self.state == None:
							self.send('', SYN, 0, 8)
					if self.state == GOT_SYN:
						self.send('', SACK, 0, 0)
				elif self.ready and (self.proto == 'icmp' or self.proto == 'udp' or self.proto == 'dns') and self.stateful:
					curr_time = int(round(time.time() * 1000))
					if not self.server:
						if self.lasthb == 0:
							self.lasthb = curr_time
						else:
							if curr_time - self.lasthb > HEART_BEAT_TIME:
								self.send('', HB, 0, 8)
								self.lasthb = int(round(time.time() * 1000))
								self.state = WAIT_ACK
			time.sleep(0.05)
		if not self.error and self.stateful and self.ready:
			if self.server:
				self.state = WAIT_ACK
			else:
				self.state = WAIT_HB
			self.send('', FIN)
		self.recvthread.running = False
		if self.recvthread.isAlive():
			self.recvthread.join()
		try:
			self.s.close()
			self.c.close()
		except:
			pass

class stdThread(threading.Thread):
	def __init__(self, opts, cmd = ''):
		threading.Thread.__init__(self)
		self.running = True
		self.error = False
		self.done = False
		self.oq = Queue(maxsize=0)
		self.oqlocked = False
		self.ready = True
		self.opts = opts
		self.compress = None
		self.cmd = cmd
		self.inp = None
		self.outp = None
		if self.cmd == '':
			self.proc = sys
			self.outp = sys.stdout
			self.inp = sys.stdin
		else:
			self.proc = subprocess.Popen(['/bin/bash'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			flags = fcntl(self.proc.stdout, F_GETFL)
			fcntl(self.proc.stdout, F_SETFL, flags | O_NONBLOCK)
			self.outp = self.proc.stdin
			self.inp = self.proc.stdout
		if 'd' in opts:
			self.compress = DECOMPRESS
	def send(self, msg):
		if self.compress == DECOMPRESS:
			msg = zlib.decompress(msg)
		self.outp.write(msg)
		if self.cmd == '':
			self.outp.flush()
	def run(self):
		while self.running:
			if not self.error and not self.done:
				msg = ''
				while self.inp in select.select([self.inp],[],[], 0)[0]:
					#line = self.inp.readline()
					line = read(self.inp.fileno(), 1024)
					if line:
						msg = msg + line
					else:
						self.done = True
						break
				if msg != '':
					self.oq.put(msg)
			time.sleep(0.1)
def help():
	print '''usage: wildcat.py [-h] -u url [-o options]

WildCat - netcat all the things!!

modes supported:
  tcp  standard tcp connection, supports compression
  udp  standard unreliable udp connection, supports compression and reliability add-on
  icmp standard icmp connection, typically "one-way", supports compression and reliability add-on
  dns  requires ownership of a DNS name that points to the IP where your wildcat listener is deployed

arguments:
  -h, --help  show this help message and exit
  -u  data source url in format proto://localip:port[:destip]
      e.g. tcp://127.0.0.1:8080 for a listener on the lo using tcp on port 8080
      e.g. icmp://0.0.0.0:0:192.168.1.1 for a client on all ints using icmp to 192.168.1.1
  -o  data source options in the form of a comma-separated string
      e.g. -o cr for compression and reliable connection
	r     "reliable" connection (only applies to UDP, ICMP, DNS, and NTP connections
	c|d   compress or decompress traffic using zlib compression
	dns=  DNS server name to use in DNS relay connection

data source options:
'''

def main():
	compression = False
	running = True
	ready = False
	taps = []
	threads = []
	if len(sys.argv) == 1:
		help()
		sys.exit(1)
	args = ' '.join(sys.argv[1:])
	params = re.findall('-.', args)
	if params[0] != '-u':
		help()
		sys.exit(1)
	last = '-u'
	for i in params:
		if last == '-o' and i == '-o':
			help()
			sys.exit(1)
		last = i
		if i != '-u' and i != '-o':
			help()
			sys.exit(1)
	args = re.split('\s*-u\s*', args)
	args = filter(None, args)
	argss = []
	for i in args:
		argss.append(re.split('\s*-o\s*', i))

	for i in argss:
		opts = ''
		if len(i) > 1:
			opts = i[1]
		if i[0] == 'std':
			sys.stderr.write('[*] Starting stdin.\n')
			t = stdThread(opts)
			threads.append(t)
		elif i[0] == 'cmd':
			sys.stderr.write('[*] Starting command.\n')
			t = stdThread(opts, 'abcd')
			threads.append(t)
		elif i[0][0:6] == 'tcp://' or i[0][0:6] == 'udp://' or i[0][0:7] == 'icmp://' or i[0][0:6] == 'dns://':
			proto = i[0].split(':')[0]
			ip = i[0].split(proto + '://')[1].split(':')[0]
			port = i[0].split(proto + '://')[1].split(':')[1]
			remote = ''
			if len(i[0].split(proto + '://')[1].split(':')) > 2:
				remote = (i[0].split(proto + '://')[1].split(':')[2], int(port))
			sys.stderr.write('[*] Opening socket on ' + proto + ' ' + ip + '\n')
			t = ipserverThread(ip, port, proto, remote, opts)
			threads.append(t)
		else:
			help()
			running = False
	if running:
		for i in threads:
			i.start()
	try:
		while len(threads) > 0 and running:
			done = False
			queuesempty = True
			for t in threads:
				if t.error == True:
					t.running = False
					running = False
				if not t.oq.empty():
					queuesempty = False
				if t.done == True:
					done = True
			if done and queuesempty:
				running = False
			if not ready:
				ready = True
				for t in threads:
					if not t.ready:
						ready = False
			else:
				for t in threads:
					if not t.oqlocked and not t.oq.empty():
						msg = ''
						while not t.oq.empty():
							msg += t.oq.get()
							name = t.name
						if msg != '':
							for t2 in threads:
								if t2.name != name:
									t2.send(msg)
				threads = [t for t in threads if t.isAlive()]
			time.sleep(0.1)
	except KeyboardInterrupt:
		running = False
	sys.stderr.write('Shutting down...\n')
	for t in threads:
		t.running = False
		t.join()
	sys.stderr.write('Quit.\n')
		
if __name__ == '__main__':
	main()

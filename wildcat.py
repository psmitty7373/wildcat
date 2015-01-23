#!/usr/bin/python

import argparse, random, re, select, socket, struct, sys, threading, time, zlib
from threading import Thread
from Queue import Queue

HEART_BEAT_TIME = 5000
RETRANSMIT_TIME = 1000
NETWORK_TIMEOUT = 30000
ICMP_PKT_SIZE = 10

ICMP_CODE = socket.getprotobyname('icmp')
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

def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

def tcpclient(host, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host,port))
	while True:
		data = s.recv(1024)
		if data == '':
			break
		print data
	s.close()

class ipserverThread(threading.Thread):
	def __init__(self, ip, port, proto, remote, opts):
		threading.Thread.__init__(self)
		self.oq = Queue(maxsize=0)
		self.oqlocked = False
		self.ip = ip
		self.port = port
		self.proto = proto
		self.server = False
		self.serverid = 0
		self.remote = remote
		self.opts = opts
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
		self.covert = False
		self.compress = None
		self.lseq = 0
		self.rseq = 0
		self.magic = 0
		self.lasthb = 0
		self.magic = random.randint(0,255)
		if remote == '':
			self.server = True
			self.serverid = self.magic
		if opts.find('r') != -1:
			self.stateful = True
		if 'c' in opts:
			self.compress = COMPRESS
		if 'd' in opts:
			self.compress = DECOMPRESS
		self.recvthread = threading.Thread(target=self.recv)
		self.recvthread.daemon = True
		self.recvthread.start()
		print self.port

	def openSocket(self):
		try:
			if self.proto == 'tcp':
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			elif self.proto == 'udp':
				self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
			elif self.proto == 'icmp':
				self.s = socket.socket(socket.AF_INET,socket.SOCK_RAW, ICMP_CODE)
			else:
				return False
			if not self.proto == 'icmp' and self.server:
				self.s.bind((self.ip,int(self.port)))
			if self.proto == 'tcp':
				self.s.listen(1)
		except:
			sys.stderr.write('[!] Unable to open socket.\n')
			return False
		sys.stderr.write('[*] Listening on port ' + str(self.port) + '\n')
		return True

	def icmp_cksum(self, msg):
		sum = 0
		count_to = (len(msg) / 2) * 2
		count = 0
		while count < count_to:
			this_val = ord(msg[count + 1])*256+ord(msg[count])
			sum = sum + this_val
			sum = sum & 0xffffffff
			count = count + 2
		if count_to < len(msg):
			sum = sum + ord(msg[len(msg) - 1])
			sum = sum & 0xffffffff
		sum = (sum >> 16) + (sum & 0xffff)
		sum = sum + (sum >> 16)
		answer = ~sum
		answer = answer & 0xffff
		answer = answer >> 8 | (answer << 8 & 0xff00)
		return answer

	def icmp_make(self, msg, type):
		header = struct.pack('bbHHh', type, 0, 0, self.serverid, 1)
		cksum = self.icmp_cksum(header + msg)
		header = struct.pack('bbHHh', type, 0, socket.htons(cksum), self.serverid, 1)
		return header + msg

	def send(self, msg, flag=PSH, seq=-1, type=8):
		if self.proto == 'icmp' or self.proto == 'udp':
			if self.compress == COMPRESS and msg != '':
				msg = zlib.compress(msg)
			n = ICMP_PKT_SIZE
			msgs = [msg[i:i+n] for i in range(0, len(msg), n)]
			if len(msgs) == 0:
				msgs.append('')
			if self.stateful:
				if flag == PSH or flag == BEGSTREAM or flag == ENDSTREAM:
					if not self.server:
						self.state = WAIT_ACK
					else:
						self.state = WAIT_HB
						type = 0
			if self.compress == COMPRESS and flag == PSH:
				self.send('', BEGSTREAM, 0)
			for i in msgs:
				if self.stateful:
					if flag != ACK:
						seq = self.lseq;
					successful = False
					while not successful:
						curr_time = int(round(time.time() * 1000))
						i = chr(self.magic) + chr(flag) + chr(seq) + i
						while self.state == WAIT_HB:
							time.sleep(0.001)
							timeout = int(round(time.time() * 1000))
							if curr_time - timeout > NETWORK_TIMEOUT:
								sys.stderr.write('[!] Connection timed out!\n')
								self.error = True
								return False
						if self.proto == 'icmp':
							packet = self.icmp_make(i, type)
						else:
							packet = i
						self.s.sendto(packet, (self.remote))
						if flag != ACK:
							self.state = WAIT_ACK
						# Retransmission timer / WAIT_ACK handler
						if flag != ACK: 
							start_time = int(round(time.time() * 1000))
							timeout = int(round(time.time() * 1000))
							while (self.state == WAIT_ACK) and self.running:
								time.sleep(0.001)
								curr_time = int(round(time.time() * 1000))
								if curr_time - timeout > NETWORK_TIMEOUT:
									sys.stderr.write('[!] Connection timed out!\n')
									self.error = True
									return False
								if curr_time - start_time > RETRANSMIT_TIME:
									if not self.server:
											self.state = WAIT_HB
											continue	
									self.s.sendto(packet, (self.remote))
									start_time = int(round(time.time() * 1000))
						successful = True
				else:
					if self.proto == 'icmp':
						packet = self.icmp_make(i, type)
					else:
						packet = i
					self.s.sendto(packet, (self.remote))
			if self.compress == COMPRESS and flag == PSH:
				self.send('', ENDSTREAM, 0)
		else:
			self.c.sendall(msg)

	def recv(self):
		while self.running and not self.error:
			if not self.ready and self.proto == 'tcp':
				inp, outp, excpt = select.select([self.s],[],[],0.0001)
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
						if self.proto == 'udp' or self.proto == 'icmp':
							data, addr = self.s.recvfrom(16384)
							if self.proto == 'icmp' or self.proto == 'udp':
								if self.proto == 'icmp':
									icmp_hdr = data[20:28]
									type, code, chksum, id, seq = struct.unpack('bbHHh', icmp_hdr)
									data = data[28:]
								if self.stateful:
									magic = ord(data[0])
									flag = ord(data[1])
									seq = ord(data[2])
									data = data[3:]
									#sys.stderr.write('M:' + str(magic) + ' F:' + str(flag) + ' S:' + str(seq) + ' D:' + data + '\n')
									if magic != self.magic:
										self.lasthb = int(round(time.time() * 1000))
										if flag == SYN and not self.ready:
											self.remote = addr
											self.state = GOT_SYN
											self.serverid = magic
										if flag == SACK and not self.ready:
											if self.state == WAIT_ACK and seq == self.lseq:
												#self.lseq += 1
												self.state = IDLE
												self.ready = True
												self.send('', ACK, 0, 8)
												sys.stderr.write('[*] Connection to ' + self.remote[0] + ' established.\n')
										elif flag == ACK:
											if seq == self.lseq:
												if self.ready:
													self.lseq += 1
												if self.state == WAIT_ACK:
													self.state = IDLE
													if not self.ready:
														self.ready = True
														sys.stderr.write('[*] Connection from ' + addr[0] + '\n')
											else:
												print 'OUT OF SYNC'
										elif flag == PSH:
											if seq != self.rseq:
												print 'OUT OF SYNC2'
											self.send('', ACK, seq, 0)
											self.rseq += 1
										elif flag == BEGSTREAM:
											self.oqlocked = True
											self.send('', ACK, seq, 0)
											self.rseq += 1
										elif flag == ENDSTREAM:
											self.oqlocked = False
											self.send('', ACK, seq, 0)
											self.rseq += 1
										elif flag == FIN:
											sys.stderr.write('[*] Connection from ' + addr[0] + ' closed.\n')
											self.error = True
											self.send('', ACK, seq, 0)
										elif flag == HB:
											if self.state != WAIT_HB:
												self.send('', ACK, seq, 0)
											else:
												self.state = GOT_HB
											self.rseq += 1
										if self.lseq > 254:
											self.lseq = 0
										if self.rseq > 254:
											self.rseq = 0
									else:
										data = ''
						elif self.proto == 'tcp':
							data = self.c.recv(16384)
						if self.proto == 'tcp' and len(data) == 0:
							sys.stderr.write('[!] Connection from ' + self.addr + ' lost.\n')
							self.error = True
							break
						else:
							if data != '':
								self.oq.put(data)
						inp, outp, excpt = select.select(self.input,[],[],0)
			time.sleep(0.1)

	def run(self):
		if (self.proto == 'udp' or self.proto == 'icmp') and not self.stateful:
			self.ready = True
		if not self.openSocket():
			self.error = True
		else:
			self.input = [self.s]
			self.c = self.s
		while self.running:
			if not self.error:
				if not self.ready and (self.proto == 'icmp' or self.proto == 'udp') and self.stateful:
					if not self.server:
						if self.state == None:
							self.send('', SYN, 0, 8)
					if self.state == GOT_SYN:
						self.send('', SACK, 0, 0)
				elif self.ready and (self.proto == 'icmp' or self.proto == 'udp') and self.stateful:
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
			self.state = WAIT_ACK
			self.send('', FIN)
		try:
			self.s.close()
			sefl.c.close()
		except:
			pass

class stdThread(threading.Thread):
	def __init__(self, opts):
		threading.Thread.__init__(self)
		self.running = True
		self.error = False
		self.done = False
		self.oq = Queue(maxsize=0)
		self.oqlocked = False
		self.ready = True
		self.opts = opts
		self.compress = None
		if 'd' in opts:
			self.compress = DECOMPRESS
	def send(self, msg):
		if self.compress == DECOMPRESS:
			msg = zlib.decompress(msg)
		sys.stdout.write(msg),
		sys.stdout.flush()
	def run(self):
		while self.running:
			if not self.error and not self.done:
				msg = ''
				while sys.stdin in select.select([sys.stdin],[],[], 0)[0]:

					line = sys.stdin.readline()
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

WildCat

arguments:
  -h, --help  show this help message and exit
  -u  data source url in format proto://listenip:port[:destip]
      e.g. tcp://127.0.0.1:8080 for a listener on the lo using tcp on port 8080
      e.g. icmp://0.0.0.0:0:192.168.1.1 for a client on all ints using icmp to 192.168.1.1
  -o  data source options in the form of a non-spaced string
	r  "reliable" connection (only applies to UDP, ICMP, DNS, and NTP connections

data source options:
'''

def main():
	compression = False
	running = True
	ready = False
	taps = []
	threads = []
	spinner = spinning_cursor()
	
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
		last = i
		if i != '-u' and i != '-o':
			help()
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
			t.start()
		elif i[0][0:6] == 'tcp://' or i[0][0:6] == 'udp://' or i[0][0:7] == 'icmp://':
			proto = i[0].split(':')[0]
			ip = i[0].split(proto + '://')[1].split(':')[0]
			port = i[0].split(proto + '://')[1].split(':')[1]
			remote = ''
			if len(i[0].split(proto + '://')[1].split(':')) > 2:
				remote = (i[0].split(proto + '://')[1].split(':')[2], int(port))
			sys.stderr.write('[*] Starting socket on ' + proto + ' ' + ip + ':' + port + '\n')
			t = ipserverThread(ip, port, proto, remote, opts)
			t.start()
			threads.append(t)
		else:
			help()
			running = False
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
			#sys.stdout.write(spinner.next())
			#sys.stdout.flush()
			time.sleep(0.1)
			#sys.stdout.write('\b')

	except KeyboardInterrupt:
		running = False

	sys.stderr.write('Shutting down...\n')
	for t in threads:
		t.running = False
		t.join()
	sys.stderr.write('Quit.\n')
		
if __name__ == '__main__':
	main()

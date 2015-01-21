#!/usr/bin/python

import argparse, random, re, select, socket, struct, sys, threading, time, zlib
from threading import Thread
from Queue import Queue

ICMP_CODE = socket.getprotobyname('icmp')
ICMP_PKT_SIZE = 512
SYN = 0
ACK = 1
SACK = 2
PSH = 3
EOF = 4

IDLE = 0
SYN_SENT = 1
WAIT_ACK = 2
ACK_SENT = 3


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
		self.ip = ip
		self.port = port
		self.proto = proto
		self.remote = remote
		self.opts = opts
		self.running = True
		self.error = False
		self.ready = False
		self.s = None
		self.c = None
		self.addr = None
		self.input = None
		self.stateful = True
		self.state = None
		self.covert = False
		self.lseq = 0
		self.rseq = 0
		if proto == 'icmp':
			self.magic = random.randint(0,255)
		self.recvthread = Thread(target = self.recv)
		self.recvthread.start()

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
			if not self.proto == 'icmp':
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

	def icmp_make(self, msg):
		header = struct.pack('bbHHh', 8, 0, 0, self.magic, 1)
		cksum = self.icmp_cksum(header + msg)
		header = struct.pack('bbHHh', 8, 0, socket.htons(cksum), self.magic, 1)
		return header + msg

	def send(self, msg, flag=PSH, seq=-1):
		if self.proto == 'icmp':
			if seq == -1:
				seq = self.lseq
			n = ICMP_PKT_SIZE
			msgs = [msg[i:i+n] for i in range(0, len(msg), n)]
			if len(msgs) == 0:
				print 'APPENDING'
				msgs.append('')
			for i in msgs:
				if (flag == SACK and not self.ready) or flag == PSH:
					self.state = WAIT_ACK
				msg = chr(self.magic) + chr(flag) + chr(seq) + i
				packet = self.icmp_make(msg)
				self.s.sendto(packet, (self.remote, 0))
				if flag == PSH:
					while self.state == WAIT_ACK:
						time.sleep(0.001)
		else:
			self.c.sendall(msg)

	def recv(self):
		while self.running:
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
					inp, outp, excpt = select.select(self.input,[],[],0.0001)
					if inp:
						if self.proto == 'udp' or self.proto == 'icmp':
							data, addr = self.s.recvfrom(16384)
							if self.proto == 'icmp':
								icmp_hdr = data[20:28]
								type, code, chksum, id, seq = struct.unpack('bbHHh', icmp_hdr)
								if id != self.magic and type == 8:
									data = data[28:]
								else:
									continue
								magic = ord(data[0])
								flag = ord(data[1])
								seq = ord(data[2])
								data = data[3:]
								#print 'M:',magic,'F:',flag,'S:',seq,'D:',data
								if magic != self.magic and type == 8:
									if flag == SYN and not self.ready:
										self.remote = addr[0]
										self.send('', SACK, 0)
										self.state = WAIT_ACK
									if flag == SACK and not self.ready:
										if self.state == SYN_SENT:
											self.state = IDLE
											self.ready = True
											self.send('', ACK, 0)
											sys.stderr.write('[*] Connection to ' + self.remote + ' established.\n')
									elif flag == ACK:
										self.lseq += 1
										if self.lseq > 254:
											self.lseq = 0
										if self.state == WAIT_ACK:
											self.state = IDLE
											if not self.ready:
												self.ready = True
												sys.stderr.write('[*] Connection from ' + addr[0] + '\n')
									elif flag == PSH:
										self.rseq = seq
										self.send('', ACK, seq)
									
						elif self.proto == 'tcp':
							data = self.c.recv(16384)
						if self.proto == 'tcp' and len(data) == 0:
							sys.stderr.write('[!] Connection from ' + self.addr + ' lost.\n')
							self.error = True
							break
						else:
							if data != '':
								self.oq.put(data)
	
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
				#send
				if not self.ready and self.proto == 'icmp':
					if self.remote != '':
						if self.state == None:
							self.send('', SYN, 0)
							self.state = SYN_SENT
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
		self.oq = Queue(maxsize=0)
		self.ready = True
		self.opts = opts
	def send(self, msg):
		sys.stdout.write(msg),
		sys.stdout.flush()
	def run(self):
		input = [sys.stdin]
		while self.running:
			inp, outp, excpt = select.select(input,[],[], 0)
			for x in inp:
				if x == sys.stdin:
					a = sys.stdin.readline()
					self.oq.put(a)
def help():
	print '''usage: wildcat.py [-h] -u url [-o options]

WildCat

arguments:
  -h, --help  show this help message and exit
  -u  data source url in format proto://listenip:port[:destip]
      e.g. tcp://127.0.0.1:8080 for a listener on the lo using tcp on port 8080
      e.g. icmp://0.0.0.0:0:192.168.1.1 for a client on all ints using icmp to 192.168.1.1
  -o  data source options in the form of a non-spaced string

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
				remote = i[0].split(proto + '://')[1].split(':')[2]
			sys.stderr.write('[*] Starting socket on ' + proto + ' ' + ip + ':' + port + '\n')
			t = ipserverThread(ip, port, proto, remote, opts)
			t.start()
			threads.append(t)
		else:
			help()
			running = False
	try:
		while len(threads) > 0 and running:
			if not ready:
				ready = True
				for t in threads:
					if not t.ready:
						ready = False
			else:
				for t in threads:
					if t.error == True:
						t.running = False
						running = False
					while not t.oq.empty():
						msg = t.oq.get()
						name = t.name
						for t2 in threads:
							if t2.name != name:
								t2.send(msg)
				threads = [t for t in threads if t.isAlive()]
			time.sleep(0.01)

	except KeyboardInterrupt:
		running = False

	sys.stderr.write('Shutting down...\n')
	for t in threads:
		t.running = False
		t.join()
	sys.stderr.write('Quit.\n')
		
if __name__ == '__main__':
	main()

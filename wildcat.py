#!/usr/bin/python

import argparse, random, select, socket, struct, sys, threading, time, zlib
from Queue import Queue

ICMP_CODE = socket.getprotobyname('icmp')

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
	def __init__(self, ip, port, proto, dir, compression):
		threading.Thread.__init__(self)
		self.oq = Queue(maxsize=0)
		self.ip = ip
		self.port = port
		self.proto = proto
		self.dir = dir
		self.compression = compression
		self.running = True
		self.error = False
		self.ready = False
		self.s = None
		self.c = None
		self.addr = None
		self.input = None
		self.stateful = True
		self.covert = False
		self.lseq = None
		self.rseq = None
		if proto == 'icmp':
			self.magic = random.randint(1,23)

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
			print '[!] Unable to open socket.'
			return False
		print '[*] Listening on port', self.port
		return True

	def icmp_cksum(self, msg):
		sum = 0
		count_to = (len(msg) / 2) * 2
		count = 0
		while count < count_to:
			this_val = ord(msg[count + 1])*256+ord(msg[count])
			sum = sum + this_val
			sum = sum & 0xffffffff # Necessary?
			count = count + 2
		if count_to < len(msg):
			sum = sum + ord(msg[len(msg) - 1])
			sum = sum & 0xffffffff # Necessary?
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

	def send(self, msg):
		if self.compression:
			self.c.sendall(zlib.decompress(msg))
		else:
			if self.proto == 'icmp':
				n = 512
				msgs = [msg[i:i+n] for i in range(0, len(msg), n)]
				for i in msgs:
					packet = self.icmp_make(msg)
					self.s.sendto(packet, (self.ip, 0))
			else:
				self.c.sendall(msg)

	def run(self):
		if self.proto == 'udp' or self.proto == 'icmp':
			self.ready = True
		if not self.openSocket():
			self.error = True
		else:
			self.input = [self.s]
			self.c = self.s
		while self.running:
			if not self.error:
				if self.proto == 'tcp' and not self.ready:
					inp, outp, excpt = select.select([self.s],[],[],0.0001)
					for x in inp:
						if x == self.s:
							try:
								self.c, self.addr = self.s.accept()
								self.ready = True
								self.input = [self.c]
								self.c.setblocking(0)
								print '[*] Connection from', self.addr
							except:
								print '[!] Connection error.'
								self.error = True
								self.running = False
				else:
					inp, outp, excpt = select.select(self.input,[],[],0.0001)
					if inp:
						if self.proto == 'udp' or self.proto == 'icmp':
							data, addr = self.s.recvfrom(16384)
							icmp_hdr = data[20:28]
							type, code, chksum, id, seq = struct.unpack('bbHHh', icmp_hdr)
							if id != self.magic and type == 8:
								data = data[28:]
							else:
								continue
						elif self.proto == 'tcp':
							data = self.c.recv(16384)
						if len(data) == 0:
							print '[!] Connection from', self.addr, 'lost.'
							self.error = True
							break
						else:
							if self.compression:
								self.oq.put(zlib.compress(data))
							else:
								self.oq.put(data)
		try:
			self.s.close()
			sefl.c.close()
		except:
			pass

class stdThread(threading.Thread):
	def __init__(self, compression):
		threading.Thread.__init__(self)
		self.running = True
		self.error = False
		self.oq = Queue(maxsize=0)
		self.ready = True
		self.compression = compression
	def send(self, msg):
		if self.compression:
			sys.stdout.write(zlib.decompress(msg).strip()),
		else:
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
					print 'SENDING THIS:',a,'<<<'

def main():
	compression = False
	running = True
	ready = False
	bis = []
	ins = []
	outs = []
	threads = []

	p = argparse.ArgumentParser(description='WildCat')
	p.add_argument('-c', dest='compress', action='store_true', help='Enable zlib compression.')
	p.add_argument('-v', dest='verbose', action='store_true', help='Verbose mode.')
	p.add_argument('-bi', dest='bis', default=[], action='append', help='Bi-directional data source.')
	p.add_argument('-in', dest='ins', default=[], action='append', help='Input only data source.')
	p.add_argument('-out', dest='outs', default=[], action='append', help='Output only data source.')
	args = p.parse_args()

	if len(sys.argv) == 1:
		p.print_help()
		sys.exit(1)

	if args.compress:
		compression = True

	for i in args.bis:
		if i == 'std':
			print '[*] Starting stdin.'
			t = stdThread(compression)
			threads.append(t)
			t.start()
		elif i[0:6] == 'tcp://' or i[0:6] == 'udp://' or i[0:7] == 'icmp://':
			proto = i.split(':')[0]
			ip = i.split(proto + '://')[1].split(':')[0]
			port = i.split(proto + '://')[1].split(':')[1]
			print '[*] Starting socket on', proto, ip, ':', port
			t = ipserverThread(ip, port, proto, 'both', compression)
			t.start()
			threads.append(t)
		else:
			p.print_help()
			sys.exit(1)
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

	print 'Shutting down...'
	for t in threads:
		t.running = False
		t.join()
	print 'Quit.'
		
if __name__ == '__main__':
	main()

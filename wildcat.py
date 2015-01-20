#!/usr/bin/python

import argparse, select, socket, sys, threading, time
from Queue import Queue

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
	def __init__(self, ip, port, proto, dir):
		threading.Thread.__init__(self)
		self.oq = Queue(maxsize=0)
		self.ip = ip
		self.port = port
		self.proto = proto
		self.dir = dir
		self.running = True
		self.error = False
		self.s = None
		self.c = None
		self.addr = None
		self.input = None

	def openSocket(self):
		try:
			if self.proto == 'tcp':
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			elif self.proto == 'udp':
				self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
			self.s.bind((self.ip,self.port))
			if self.proto == 'tcp':
				self.s.listen(1)

		except:
			print '[!] Unable to open socket.'
			return False
		print '[*] Listening on port', self.port
		return True

	def send(self, msg):
		self.c.sendall(msg)

	def run(self):
		connected = True
		if not self.openSocket():
			self.error = True
		if self.proto == 'tcp':
			connected = False
		else:
			self.input = [self.s]
			self.c = self.s
		while self.running:
			if not self.error:
				if self.proto == 'tcp' and not connected:
					inp, outp, excpt = select.select([self.s],[],[],0.0001)
					for x in inp:
						if x == self.s:
							try:
								self.c, self.addr = self.s.accept()
								connected = True
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
						if self.proto == 'udp':
							data, addr = self.s.recvfrom(16384)
						elif self.proto == 'tcp':
							data = self.c.recv(16384)
						if len(data) == 0:
							print '[!] Connection from', self.addr, 'lost.'
							self.error = True
							break
						else:
							self.oq.put(data)
		try:
			self.s.close()
			sefl.c.close()
		except:
			pass

class stdThread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.running = True
		self.error = False
		self.oq = Queue(maxsize=0)
	def send(msg):
		print msg.strip()
	def run(self):
		input = [sys.stdin]
		while self.running:
			inp, outp, excpt = select.select(input,[],[], 0)
			for x in inp:
				if x == sys.stdin:
					self.oq.put(sys.stdin.readline())


def main():
	running = True
	taps = []
	threads = []

	p = argparse.ArgumentParser(description='WildCat')
	p.add_argument('-tap', dest='taps', default=[], action='append', help='Bi-directional data source.')
	p.add_argument('-in', dest='ins', default=[], action='append', help='Input only data source.')
	p.add_argument('-out', dest='outs', default=[], action='append', help='Output only data source.')
	args = p.parse_args()

	for i in args.taps:
		if i == 'std':
			print '[*] Starting stdin.'
			t = stdThread()
			threads.append(t)
			t.start()
		elif i[0:6] == 'tcp://' or i[0:6] == 'udp://':
			proto = i[0:3]
			ip = i.split(proto + '://')[1].split(':')[0]
			port = i.split(proto + '://')[1].split(':')[1]
			print '[*] Starting tcp on', proto, ip, ':', port
			t = ipserverThread(ip, int(port), proto, 'both')
			t.start()
			threads.append(t)
	try:
		while len(threads) > 0 and running:
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

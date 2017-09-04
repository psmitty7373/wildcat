#!/usr/bin/python

# Wildcat - Netcat All The Things!
# Written by psmitty7373
# Twitter - @psmitty7373
# Github - https://github.com/psmitty7373/wildcat

import argparse, base64, os, pty, random, re, select, socket, StringIO, struct, subprocess, sys, threading, time, zlib
from fcntl import fcntl, F_GETFL, F_SETFL
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
END = '<<ENDOFCOMPRESSEDDATA'

IDLE = 0
GOT_SYN = 1
WAIT_ACK = 2
WAIT_HB = 3
GOT_HB = 4

#sysctl -w net.ipv4.icmp_echo_ignore_all=1

class ipserverThread(threading.Thread):
    def __init__(self, ip, port, proto, remote, opts):
        threading.Thread.__init__(self)
        self.oq = Queue(maxsize=0)
        self.iq = Queue(maxsize=0)
        self.oqlocked = False
        self.iqlocked = False
        self.ip = ip
        self.port = port
        self.proto = proto
        self.server = False
        self.remoteid = None
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
        self.stateful = opts['reliable']
        self.compress = opts['compression']
        self.bidirectional = opts['bidirectional']
        self.verbose = opts['verbose']
        self.state = None
        self.lseq = 0
        self.rseq = 0
        self.lasthb = 0
        self.lastq = None
        self.lastid = None
        self.dnsname = 'chaumurky.com'
        self.lastmillis = 0
        if remote == '':
            self.server = True
            self.id = random.randint(128,255)
        else:
            self.id = random.randint(0,128)
            if opts['dns'][0:4] == 'dns=' and self.proto == 'dns':
                i = opts['dns'].split('=')
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
        if self.proto == 'dns' and self.dnsname == None:
            sys.stderr.write('[!] Error! A dns=<dns.name> option is required for the DNS protocol.\n')
            self.error = True
        self.recvthread = threading.Thread(target=self.recv)
        self.recvthread.daemon = True

    def openSocket(self):
        try:
            if self.proto == 'tcp':
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        msg = base64.b64encode(msg).replace('=','-')
        qcount = 1
        binq = ''
        bina = ''
        if not self.server:
            labels = []
            millis = base64.b64encode(str(int(round(time.time() * 1000)))).replace('=','-')
            if len(msg) > 63:
                a,b = msg[:len(msg)/2],msg[len(msg)/2:]
                labels = [millis,a,b,'chaumurky','com']
            else:
                labels = [millis,msg,'chaumurky','com']
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
        if self.compress and msg != '':
            msg = zlib.compress(msg)
        # ICMP / UDP / DNS
        if self.proto == 'icmp' or self.proto == 'udp' or self.proto == 'dns':
            n = MAX_PACKET_SIZE
            if self.proto == 'dns':
                n = 90
            msgs = [msg[i:i+n] for i in range(0, len(msg), n)]
            if len(msgs) == 0:
                msgs.append('')
            if self.stateful:
                # if we need to send data, and we aren't the server, we may have to wait for a HB before sending
                if flag == PSH or flag == BEGSTREAM or flag == ENDSTREAM or flag == FIN:
                    if not self.server or self.proto == 'udp' or self.bidirectional:
                        self.state = WAIT_ACK
                    else:
                        self.state = WAIT_HB
                        type = 0
            if self.compress and flag == PSH and len(msgs) > 1:
                self.send('', BEGSTREAM, 0)
            for i in msgs:
                if self.stateful:
                    if flag != ACK:
                        seq = self.lseq;
                    successful = False
                    while not successful:
                        #sys.stderr.write('SEND: ID:' + str(self.id) + ' FLAG:' + str(flag) + ' SEQ' + str(seq) + '\n')
                        i = chr(self.id) + chr(flag) + chr(seq) + i
                        timeout = int(round(time.time() * 1000))
                        #waiting for HB timer
                        while self.state == WAIT_HB and not self.done:
                            curr_time = int(round(time.time() * 1000))
                            time.sleep(0.01)
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
                        if (flag != ACK and self.proto != 'icmp') or (flag != ACK and flag != FIN and self.proto == 'icmp'):
                            self.state = WAIT_ACK
                            start_time = int(round(time.time() * 1000))
                            timeout = int(round(time.time() * 1000))
                            while (self.state == WAIT_ACK or self.state == WAIT_HB) and self.running and not self.done:
                                time.sleep(0.01)
                                curr_time = int(round(time.time() * 1000))
                                if curr_time - timeout > NETWORK_TIMEOUT:
                                    sys.stderr.write('[!] Connection timed out!\n')
                                    self.error = True
                                    return False
                                if curr_time - start_time > RETRANSMIT_TIME:
                                    if self.server:
                                        sys.stderr.write('WAIT HB?')
                                        self.state = WAIT_HB
                                        continue
                                    try:
                                        if self.proto == 'dns': #remake dns packet
                                            packet = self.dns_make(i)
                                        self.s.sendto(packet, (self.remote))
                                    except:    
                                        sys.stderr.write('[!] Send Error 2')
                                        pass
                                        #TODO send error handling
                                    start_time = int(round(time.time() * 1000))
                        successful = True
                        if flag == PSH:
                            self.lseq += 1
                            if self.lseq > 254:
                                self.lseq = 0
                        elif flag == FIN:
                            sys.stderr.write('[!] Sent FIN!\n')
                            self.done = True
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
            if self.compress and flag == PSH and len(msgs) > 1:
                self.send('', ENDSTREAM, 0)
        else: #tcp
            try:
                if self.compress:
                    self.c.sendall(msg + END)
                else:
                    self.c.sendall(msg)
            except:
                sys.stderr.write('[!] Send error 3\n')
                pass
                #TODO send error handling

    def recv(self):
        while self.running and not self.error or (not self.done and self.stateful and self.ready and not self.error):
            # TCP Server
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
            # TCP client, UDP, ICMP, DNS
            else:
                if self.input != None:    
                    inp, outp, excpt = select.select(self.input,[],[],0)
                    while inp:
                        # UDP / ICMP / DNS
                        if self.proto == 'udp' or self.proto == 'icmp' or self.proto == 'dns':
                            data, addr = self.s.recvfrom(16384)
                            if self.remote == '' or (self.proto == 'dns' and self.server):
                                self.remote = addr
                                #sys.stderr.write('[*] Connection from ' + str(addr[0]) + '\n')
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
                                #sometimes DNS resends stuff and asks for extra stuff, check times to make sure it isn't a repeat
                                millis = int(labels[0].replace('-','=').decode('base64'))
                                if millis <= self.lastmillis:
                                    if self.verbose:
                                        sys.stderr.write('[!] Out of order / repeat DNS packet!\n')
                                        sys.stderr.write('>>>' + str(self.lastmillis) + ' > ' + str(millis) + '<<<\n')
                                    continue
                                self.lastmillis = millis
                                if acount == 0:
                                    data = ''
                                    for i in labels[1:]:
                                        data += i
                                try:
                                    data = data.replace('-','=').decode('base64')
                                except:
                                    if self.verbose:
                                        sys.stderr.write('[!] Erroneous base64 packet.\n')
                                        sys.stderr.write('>>>' + str(i) + '<<<\n')
                                    continue

                            if self.stateful and len(data) > 2:
                                sid = ord(data[0])
                                flag = ord(data[1])
                                seq = ord(data[2])
                                data = data[3:]
                                #sys.stderr.write('RECV: M:' + str(sid) + ' F:' + str(flag) + ' RXRSEQ:' + str(seq) + ' TRSEQ:' + str(self.rseq) + ' LSEQ:' + str(self.lseq) + '\n')
                                if sid != self.id:
                                    self.lasthb = int(round(time.time() * 1000))
                                    # SYN
                                    if flag == SYN and seq == 0 and data == '' and not self.ready:
                                        self.remote = addr
                                        self.state = GOT_SYN
                                        self.remoteid = sid
                                    # SYNACK
                                    elif flag == SACK and seq == 0 and data == '' and not self.ready:
                                        if self.state == WAIT_ACK and seq == self.lseq:
                                            self.state = IDLE
                                            self.ready = True
                                            self.remoteid = sid
                                            self.send('', ACK, 0, 8)
                                            sys.stderr.write('[*] Connection to ' + self.remote[0] + ' established.\n')
                                    # Packet from our remote end
                                    elif sid == self.remoteid:
                                        if flag == ACK:
                                            if seq == self.lseq:
                                                if self.state == WAIT_ACK:
                                                    if self.done:
                                                        sys.stderr.write('[!] Finished.\n')
                                                        self.error = True                    
                                                    else:
                                                        self.state = IDLE
                                                        if not self.ready:
                                                            self.ready = True
                                            elif seq < self.lseq:
                                                data = ''
                                                sys.stderr.write('[!] OUT OF SYNC!: ' + str(seq) + ' lseq: ' + str(self.lseq) +'\n')
                                            else:
                                                sys.stderr.write('[!] Something crazy happened.\n')
                                        elif flag == PSH:
                                            if seq == self.rseq:
                                                self.send('', ACK, seq, 0)
                                                self.rseq += 1
                                            elif seq < self.rseq:
                                                sys.stderr.write('[!] Acking old packet.\n')
                                                self.send('', ACK, seq, 0)
                                                data = ''
                                            else:
                                                sys.stderr.write('[!] Packets from da future?!\n')
                                                #TODO Request old packet again... semething has happened
                                        elif flag == BEGSTREAM:
                                            self.oqlocked = True
                                            self.send('', ACK, seq, 0)
                                        elif flag == ENDSTREAM:
                                            self.oqlocked = False
                                            self.send('', ACK, seq, 0)
                                        elif flag == FIN:
                                            sys.stderr.write('[*] Connection from ' + addr[0] + ' closed.\n')
                                            self.ready = False
                                            self.running = False
                                            self.send('', ACK, seq, 0)
                                            self.done = True
                                        elif flag == HB:
                                            if self.state != WAIT_HB:
                                                self.send('', ACK, seq, 0)
                                            else:
                                                self.state = GOT_HB
                                        if self.rseq > 254:
                                            self.rseq = 0
                                    else:
                                        sys.stderr.write('Sid:' + str(sid) + ' rem:' + str(self.remoteid))
                                        sys.stderr.write('Data from someone else?\n')
                                else:
                                    data = ''
                        #TCP
                        elif self.proto == 'tcp':
                            try:
                                data = self.c.recv(16384)
                                if self.compress:
                                    if END in data:
                                        self.oqlocked = False
                                    else:
                                        self.oq.locked = True
                            except:
                                sys.stderr.write('[!] Error! Recieve error.\n')
                                self.error = True
                                break
                        if self.proto == 'tcp' and len(data) == 0:
                            if self.server:
                                sys.stderr.write('[!] Connection from ' + self.addr[0] + ' lost.\n')
                            else:
                                sys.stderr.write('[!] Connection to ' + self.remote[0] + ' lost.\n')
                            self.c.close()
                            self.error = True
                            break
                        else:
                            if data != '':
                                self.oq.put(data)
                        inp, outp, excpt = select.select(self.input,[],[],0)
            time.sleep(0.01)
        if self.c:
            self.c.close()
        self.done = True

    def run(self):
        finsent = False
        if (self.proto == 'udp' or self.proto == 'icmp' or self.proto == 'dns') and not self.stateful:
            self.ready = True
        if not self.openSocket():
            self.error = True
        else:
            self.input = [self.s]
            self.c = self.s
            self.recvthread.start()
        while self.running or (self.stateful and not self.done and not self.error):
            if not self.error:
                if self.stateful and (self.proto == 'icmp' or self.proto == 'udp' or self.proto == 'dns'):
                    if not self.ready and self.running:
                        if not self.server:
                            if self.state == None:
                                self.send('', SYN, 0, 8)
                        if self.state == GOT_SYN:
                            self.send('', SACK, 0, 0)
                    elif self.ready:
                        if not self.running and not finsent:
                            finsent = True
                            self.send('', FIN)
                        curr_time = int(round(time.time() * 1000))
                        if not self.server and not finsent:
                            if self.lasthb == 0:
                                self.lasthb = curr_time
                            else:
                                if curr_time - self.lasthb > HEART_BEAT_TIME:
                                    self.state = WAIT_ACK
                                    self.send('', HB, 0, 8)
                                    self.lasthb = int(round(time.time() * 1000))
                        if not self.iqlocked and not self.iq.empty():
                            msg = ''
                            while not self.iq.empty():
                                msg += self.iq.get()
                            if msg != '':
                                self.send(msg)
                else:
                    if not self.iqlocked and not self.iq.empty():
                        msg = ''
                        while not self.iq.empty():
                            msg += self.iq.get()
                        if msg != '':
                            self.send(msg)


            time.sleep(0.05)
        self.recvthread.running = False
        if self.recvthread.isAlive():
            self.recvthread.join()
        try:
            if self.s:
                self.s.close()
        except:
            sys.stderr.write('[!] Error closing ports.')

class stdThread(threading.Thread):
    def __init__(self, opts, cmd = ''):
        threading.Thread.__init__(self)
        self.running = True
        self.error = False
        self.done = False
        self.oq = Queue(maxsize=0)
        self.iq = Queue(maxsize=0)
        self.oqlocked = False
        self.iqlocked = False
        self.ready = True
        self.opts = opts
        self.compress = opts['compression']
        self.cmd = cmd
        self.inp = None
        self.outp = None
        if self.cmd == '':
            self.proc = sys
            self.outp = sys.stdout
            self.inp = sys.stdin
        elif self.cmd == 'pty':
            self.proc = sys
            pid, self.inp = os.forkpty()
            self.outp = self.inp
            if pid == 0:
                os.execl('/bin/bash', 'bash')
        else:
            self.proc = subprocess.Popen(['/bin/bash'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            flags = fcntl(self.proc.stdout, F_GETFL)
            fcntl(self.proc.stdout, F_SETFL, flags | O_NONBLOCK)
            self.outp = self.proc.stdin
            self.inp = self.proc.stdout
    def send(self, msg):
        if self.compress:
            msg = zlib.decompress(msg)
        if type(self.outp) == int:
            os.write(self.outp, msg)
        else:
            self.outp.write(msg)
            if self.cmd == '':
                self.outp.flush()
    def run(self):
        while self.running:
            if not self.error and not self.done:
                msg = ''
                while self.inp in select.select([self.inp, 0],[],[], 0)[0]:
                    #line = self.inp.readline()
                    fd = None
                    if type(self.inp) == int:
                        fd = self.inp
                    else:
                        fd = self.inp.fileno()
                    try:
                        line = os.read(fd, 1024)
                    except:
                        pass
                    if line:
                        msg = msg + line
                    else:
                        self.done = True
                        break
                if msg != '':
                    if self.compress:
                        msg = zlib.compress(msg)
                    self.oq.put(msg)
                if not self.iqlocked and not self.iq.empty():
                    msg = ''
                    while not self.iq.empty():
                        msg += self.iq.get()
                    if msg != '':
                        self.send(msg)
            time.sleep(0.1)

def help(name=None):
    return '''usage: wildcat.py [-h] -u url [-o options]

WildCat - netcat all the things!!

modes supported:
  std  standard input / output
  tcp  standard tcp connection, supports compression
  udp  standard unreliable udp connection, supports compression and reliability add-on
  icmp standard icmp connection, typically "one-way", supports compression and reliability add-on
  dns  requires ownership of a DNS name that points to the IP where your wildcat listener is deployed
  pty  spawns a pty

usage:
  ./wildcat.py <url 1> <url 2> [opts]

arguments:
  -h   show this help message and exit

  url  data source url in format proto://localip:port[:destip]
       localip can be blank e.g. tcp://:8080
       e.g. tcp://127.0.0.1:8080 for a listener on the lo using tcp on port 8080
       e.g. icmp://0.0.0.0:0:192.168.1.1 for a client on all ints using icmp to 192.168.1.1

data source options:
  r   "reliable" connection (only applies to UDP, ICMP, DNS, and NTP connections)
       requires other endpoints to be wildcat listeners
       e.g tcp://:8080:192.168.1.2,r

  c    enable zlib compression
       e.g tcp://:8080:192.168.1.2,c
       requires other endpoints to be wildcat listeners

  b    enable bi-directional comms for typically non-bidirectional protocols
       e.g. if ICMP is allowed directly both ways

  v    verbose output

  multiple options can be applied to each url
  e.g. icmp://:8080:192.168.1.2,rcb

  d= DNS server name to use in DNS relay connection

'''

def main():
    running = True
    ready = False
    taps = []
    threads = []

    p = argparse.ArgumentParser(usage=help())
    p.add_argument('url', nargs='+')
    args = p.parse_args()

    for i in args.url:
        argsplit = i.split(',')
        url = argsplit[0]
        opts = {'reliable': False, 'compression': False, 'bidirectional': False, 'dns': '', 'verbose': False}
        if len(argsplit) > 1:
            if 'c' in argsplit[1]:
                opts['compression'] = True
            if 'r' in argsplit[1]:
                opts['reliable'] = True
            if 'b' in argsplit[1]:
                opts['bidirectional'] = True
            if 'v' in argsplit[1]:
                opts['verbose'] = True
        if url == 'std':
            sys.stderr.write('[*] Starting stdin.\n')
            t = stdThread(opts)
            threads.append(t)
        elif url == 'cmd':
            sys.stderr.write('[*] Starting command.\n')
            t = stdThread(opts, 'abcd')
            threads.append(t)
        elif url == 'pty':
            sys.stderr.write('[*] Starting command.\n')
            t = stdThread(opts, 'pty')
            threads.append(t)
        elif url[0:6] == 'tcp://' or url[0:6] == 'udp://' or url[0:7] == 'icmp://' or url[0:6] == 'dns://':
            proto = url.split(':')[0]
            ip = url.split(proto + '://')[1].split(':')[0]
            if len(ip) == 0:
                ip = '0.0.0.0'
            port = url.split(proto + '://')[1].split(':')[1]
            remote = ''
            if len(url.split(proto + '://')[1].split(':')) > 2:
                remote = (url.split(proto + '://')[1].split(':')[2], int(port))
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
                done = True
                queuesempty = True
                for t in threads:
                    if t.error == True:
                        t.running = False
                        running = False
                    if not t.oq.empty() or not t.iq.empty():
                        queuesempty = False
                    if not t.done:
                        done = False
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
                            #if t.compress:
                                #msg = zlib.decompress(msg)
                            if msg != '':
                                for t2 in threads:
                                    if t2.name != name:
                                        t2.iq.put(msg)                        
                                        #t2.send(msg)
                    threads = [t for t in threads if t.isAlive()]
                time.sleep(0.1)

        except KeyboardInterrupt:
            running = False
        sys.stderr.write('[!] Shutting down...\n')

    for t in threads:
        t.running = False
        t.join()

    sys.stderr.write('[!] Quit.\n')
    sys.exit()
        
if __name__ == '__main__':
    main()

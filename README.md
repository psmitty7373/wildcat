# wildcat
```bash
WildCat - netcat all the things!!

WildCat is an attempt to bring netcat to many different protocols in one python file.

Typical Usage: ./wildcat.py std tcp://0.0.0.0:8080
This sets up a wildcat listener on all interfaces on port 8080 and passes input and output to the stdin and stdout of the console.

WildCat allows you to pick whatever endpoints you like... want to recieve ICMP and send out on TCP?  No problem.  What to tee an incoming UDP connection to two different TCP connections... again... no problem!

For instance the last scenario would look like this: ./wildcat.py udp://0.0.0.0:1337 tcp://0.0.0.0:8080:1.1.1.1 tcp://0.0.0.0:8081:2.2.2.2

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
```

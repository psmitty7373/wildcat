# wildcat
```bash
WildCat - netcat all the things!!

WildCat is an attempt to bring netcat to many different protocols in one python file.

Typical Usage: ./wildcat.py -u std -u tcp://0.0.0.0:8080
This sets up a wildcat listener on all interfaces on port 8080 and passes input and output to the stdin and stdout of the console.

WildCat allows you to pick whatever endpoints you like... want to recieve ICMP and send out on TCP?  No problem.  What to tee an incoming UDP connection to two different TCP connections... again... no problem!

For instance the last scenario would look like this: ./wildcat.py -u udp://0.0.0.0:1337 -u tcp://0.0.0.0:8080:1.1.1.1 -u tcp://0.0.0.0:8081:2.2.2.2

modes supported:
  std  regular old std-in and std-out
  cmd  opens a command shell, supports compression
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
```

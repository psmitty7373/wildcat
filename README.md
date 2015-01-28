# wildcat
```bash
usage: wildcat.py [-h] -u url [-o options]

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
```

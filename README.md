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

A command-line packet analyzer that allows users to capture or filter network traffic.

---

## 8. Wireshark

A GUI-based network protocol analyzer used for network troubleshooting, analysis, and software development.

---

## 9. Snort

An open-source network intrusion detection and prevention system capable of real-time traffic analysis and packet logging.

---

## 📚 Further Practice

- Practice capturing traffic with TCPdump and Wireshark.
- Analyze packet structure, flags, and sessions.
- Configure basic Snort rules for intrusion detection.
- Review common protocols and services on different ports.

---

**Author:**  
*This repository is created for study and practice purposes.*

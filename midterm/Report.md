# Report



### Abstract

The QUIC protocol is receiving increasing attention from major technology companies since the establishment of standerization by IETF, and more and more QUIC implementations are being developed. As the core protocol of HTTP/3, the security of QUIC will continue to be of concern. In this regard, this report will start from the version negotiation mechanism of QUIC to introduce an request forgery attack based on this mechanism. We analyze the controllable bits of the version negotiation messages and show that this scheme can be utilized to impersonate other UDP-based protocols, e.g., DNS requests.



## 1. Background

QUIC (Quick UDP Internet Connections) is a novel transport layer protocol designed to offer faster, more reliable, and more secure network connections. Initially developed by Google, QUIC serves as an alternative to TCP and TLS for transmitting data over the Internet. It is built on top of the UDP protocol, enabling it to bypass the TCP connection establishment process, thereby reducing connection latency and enabling faster connection recovery during network switches.

The development journey of QUIC has been marked by significant milestones. Google first introduced QUIC in 2013 as an experimental protocol to address latency issues. Over time, it underwent several iterations and refinements, with the IETF (Internet Engineering Task Force) officially adopting it as an Internet standard in 2020, known as QUIC Version 1.

Various tech giants have actively researched and contributed to the advancement of QUIC. Google, being the original developer, has been a major driving force behind its development. Additionally, companies like Cloudflare, Facebook (now Meta Platforms), and Microsoft have also been actively involved in QUIC research and implementation.

As mentioned above, QUIC will keep connection persistant during network switches, allowing the peer UDP port and IP address to be changed. This mechanism is called Connection Migration in QUIC. In this situation, a server may send UDP packets to an unknown host. As a consequence, QUIC is certainly vulnerable to address spoofing and request forgery. The specification also acknowledges the vulnerabilities and provides first security considerations [3].

In this report, we take a detailed look at version negotiation request forgery attack. To this end, we focus on request forgery attacks initiated by a QUIC client (the attacker). In this scenario, request forgery induces a QUIC server (the victim) to send packets that the attacker controls. The attacker can use the server’s position in the network to gain higher privileges.

## 2. Request Forgery

### 2.1 QUIC Basics

The QUIC handshake(Fig. 3) combines the transport layer handshake and the TLS cryptographic handshake. The initial packets resemble the 3-way handshake of TCP, while the TLS parameters are carried in CRYPTO frames. All packets in the handshake use the long header format and contain a Source Connection ID (SCID) as well as a Destination Connection ID (DCID)  with the corresponding lengths.  If a server receives an unknown version, it will answer with a version negotiation packet, providing a list of supported versions. Version negotiation packets must always have the version identifier 0x00000000 [3].

### 2.2 Threat Model

Request forgery attacks occur when an attacker is able to trigger a host (victim) to send one or more “unintended” network requests to another host (target).  An attacker can leverage the request forgery for achieving two goals, which are illustrated in Fig. 4: First, utilizing the higher authority of the victim, i.e., internal/restricted network access or higher privileges. Second, utilizing the higher bandwidth available from the server to a target.

For our attacks, we assume that the attacker is able to fully control the content of packets sent to the victim, including IP address and port spoofing. We restrict the attacker to modifications of messages that are still understood by the victim as valid QUIC packets to emphasize that the examined vulnerabilities stem primarily from the protocol design.  The target does not need to be capable of speaking QUIC but at least one UDP port expects incoming datagrams. While the target might not be directly reachable from the attacker, the victim must be able to reach it.



## 2. Attack Modality

### 2.1 Version Negotiation Request Forgery (VNRF)

VNRF abuses the scheme of the QUIC handshake: A QUIC server responds with a version negotiation packet after receiving a client's initial packet of unknown version. A malicious client can send a non-existing version identifier to reliably trigger the version negotiation functionality. If the client furthermore spoofs the source of the datagram, the version negotiation is sent to the target.

### 2.1.1 Controllable Bits of Version Negotiation Packet

Version negotiation packets have simple structure shown in Fig. 8. The first bit should be 1 indicating the packet is a long header packet. The next seven bits are unused in version negotiation packets and can be set to an arbitrary value by the server [3]. The next 32 bits should be all zeros indicating a version negotiation packet. The last 32 bits of the packet contains the identifiers for supported versions, which are decided by the server. The bits discussed above are all out of attacker's control.

The only controllable bits are DCID, SCID and their corresponding lengths. The length of connection ID is 8 bits, representing a maximum length of 255 bytes, which is 2040 bits. Besides, according to the QUIC stander, the server must mirror the DCID and SCID fields of the client packets when responding a version negotiation packet. Thus, there are always totally 512 bytes of the packet controlled by the attacker.

### 2.1.2 VNRF Proof of Concept

In this section, we will design a datagram that is a valid QUIC version negotiation packet as well as a valid DNS request. This datagram could be sent by the server (the victim) and triggers a valid DNS response sent by a DNS server. Here, DNS is just an example, which is widely used UDP-based protocol. There are numbers of UDP-based protocols in the networks while some of them may be impersonated through VNRF.

We try to construct a DNS request for the domain *www.baidu.com*. Fig. 10 shows the beginning of the handcrafted packet bytes with the QUIC interpretation (above) and DNS interpretation (below). The first byte of the QUIC packet will start with a one, to indicate the long header followed by seven bits with random value. This byte plus the first zero-byte of the version identifier will be interpreted as the query ID. The next two zero-bytes of the version number are interpreted as the DNS flags defined in RFC 1035 [21].  The DNS flags for the two zero-bytes indicate a standard query that is not truncated with no recursion desired. This is a valid flag setting for DNS queries. The last version byte is the first byte of the number of host queries contained in the DNS query. The second byte of the number of queries is determined by the DCID length of the QUIC version negotiation packet. 

For DCID length, we chose a fixed value of seven to keep the amount of required hostnames in the query to a minimum, while still being able to skip the remaining bytes of the answer number (Ans), the number of authority records (Auth), and the additional records number (Add). The Ans and Auth bytes should be zero for a normal query and are not usable to extend the payload. The number of additional records is usually zero for a standard DNS query. However, we set the two Add bytes to 0x0001 to deal with the remaining version number identifiers of the version negotiation packet that follow the CIDs.

The last byte of DCID is the label counts in the DNS query, representing the number of characters before first dot of the domain name to be queried. The SCID length is the first byte of the hostname www.baidu.com.  Each domain level is indicated by a length octet and the top-level domain is terminated by a zero-byte.  With the SCID length set to *w* (0x77), there are 119 remaining bytes of SCID that can be utilized for the remaining payload. This size is sufficient to include the entire query for www.baidu.com.

Six further queries to the root domain were added to have the required seven queries in total. The hostnames for padding can be arbitrary and are only required to adhere to the DNS specification. The root domain is most suitable to our needs as it consumes as little payload space as possible. The Add section query entry was set to the domain root (0x00) and the type and class was set to zero. The length of the Add entry is set to the length of the remaining SCID payload plus the length of the version identifier array in the version negotiation packet. The amount of version identifiers advertised by the server is static and can be determined by triggering a version negotiation without a spoofed address. The length of the array is multiplied by four, because version identifiers are always 4 byte values and the Add entry length is given in bytes. The remaining payload space between the beginning of the Add entry and the version identifiers are filled with random bytes. By encoding the remaining QUIC payload in the described manner, the additional record will not make sense to a DNS server. Yet, the whole packet bytes are covered and the forged request is a valid DNS request [21].

Fig. 11 shows the packet capture of a VNRF-based protocol impersonation with a payload as described above. To demonstrate the validity of the forged packet, the entire QUIC traffic (left) is also decoded as DNS (right) in Wireshark. To execute a real DNS query, the spoofed address was set to the Google DNS server 8.8.8.8:53. Accordingly, Fig. 11a shows the packet types, Fig. 11b shows the first header byte and version, and Fig. 11c shows the CIDs in the payload. While the initial packet is a malformed DNS packet, the right pane shows that the version negotiation packet is indeed interpreted as a valid DNS request to www.baidu.com (Fig. 11d) and results in a valid DNS response containing the IP addresses (see Fig. 11e).

The proof of concept above shows that protocol impersonation with VNRF can be used with a “real-world” protocol. Due to the uncovered restrictions, creating a payload for other protocols than DNS will likely require a lot of debugging and manual tweaking to find a valid combination of bytes. There will be some payloads that cannot be realized within the existing boundaries, as described above. Nevertheless, we are convinced that a number of correct datagrams can be crafted through multiple iterations and creativity in utilizing the specification of the targeted protocol.

### 2.1.3 VNRF Drawback

The proof of concept discussed above is run on two virtual machine with Ubuntu 20.04 LTS system. However, while running the same code on two Tencent Cloud lighthouse (a light-weight cloud server), it did not work. According to our conjecture, the reason is that the packets sent from port 53 will be blocked by firewalls. Normally a DNS server will never send packets proactively to any host.

# Report



### Abstract

With the establishment of standards, the QUIC protocol is receiving increasing attention from major technology companies, and more and more QUIC implementations are being developed. As the core protocol of HTTP/3, the security of QUIC will continue to be of concern. In this regard, this report will start from the version negotiation mechanism of QUIC to introduce an request forgery attack based on this mechanism. We analyze the controllable attack space of the respective protocol messages and demonstrate that one of the attack modalities can indeed be utilized to impersonate other UDP-based protocols, e.g., DNS requests.



## 1. Introduction

### 1.1 QUIC Basis

The QUIC protocol is an innovative development of transport layer stream abstraction. It combines the capabilities of TCP and TLS 1.3 to reduce the amount of required round-trip times (RTTs) during the connection setup. It can achieve a true 0-RTT connection setup for known endpoints, improving performance in high-latency networks [1]. With recent standardization efforts of the QUIC protocol by the IETF in 2021 [2]–[5] and through the support of many well known companies like Apple, Cloudflare, Facebook, Google, and Mozilla, QUIC is gaining more traction. Lastly, QUIC’s importance increased by choosing it to be the core protocol of the new HTTP/3 standard. The adoption of QUIC results in one of the biggest changes to the web’s protocol stack [6] and spawned the development of various new implementations [7]. 

In order to achieve compatibility with the Internet protocol stack, QUIC was built on top of UDP [3]. While providing transport layer functionality, QUIC is technically an application layer protocol with its own addressing scheme [1]. QUIC’s addressing allows the underlying UDP port and IP address to change, while the connection persists. The QUIC protocol handles the migration of endpoints. To this end, a server has to send UDP datagrams to an unknown endpoint.

As a consequence, QUIC seems particularly vulnerable to address spoofing and request forgery. The specification acknowledges the vulnerabilities and provides first security considerations [3].

In this report, we take a detailed look at version negotiation request forgery attack. To this end, we focus on request forgery attacks initiated by a QUIC client (the attacker). In this scenario, request forgery induces a QUIC server (the victim) to send packets that the attacker controls. The attacker can use the server’s position in the network to gain higher privileges.

The QUIC handshake(Fig. 3) combines the transport layer handshake and the TLS cryptographic handshake. The initial packets resemble the 3-way handshake of TCP, while the TLS parameters are carried in CRYPTO frames. All packets in the handshake use the long header format and contain a Source Connection ID (SCID) as well as a Destination Connection ID (DCID)  with the corresponding lengths.  If a server receives an unknown version, it will answer with a version negotiation packet, providing a list of supported versions. Version negotiation packets must always have the version identifier 0x00000000 [3].

### 1.2 Request Forgery Model

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

For our payload, we chose a value of seven to keep the amount of required hostnames in the query to a minimum, while still being able to skip the remaining bytes of the answer number (Ans), the number of authority records (Auth), and the additional records number (Add). The Ans and Auth bytes should be zero for a normal query and are not usable to extend the payload. The number of additional records is usually zero for a standard DNS query. However, we set the two Add bytes to 0x0001 to deal with the remaining version number identifiers of the version negotiation packet that follow the CIDs.


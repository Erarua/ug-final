# Report



### Abstract

With the establishment of various standards, the QUIC protocol is receiving increasing attention from major technology companies, and more and more QUIC implementations are being developed. As the core protocol of HTTP/3, the security of QUIC will continue to be of concern. In this regard, this report will start from the version negotiation mechanism of QUIC to introduce an request forgery attack based on this mechanism. We analyze the controllable attack space of the respective protocol messages and demonstrate that one of the attack modalities can indeed be utilized to impersonate other UDP-based protocols, e.g., DNS requests.



## 1. Introduction

The QUIC protocol is an innovative development of transport layer stream abstraction. It combines the capabilities of TCP and TLS 1.3 to reduce the amount of required round-trip times (RTTs) during the connection setup. It can achieve a true 0-RTT connection setup for known endpoints, improving performance in high-latency networks [1]. With recent standardization efforts of the QUIC protocol by the IETF in 2021 [2]–[5] and through the support of many well known companies like Apple, Cloudflare, Facebook, Google, and Mozilla, QUIC is gaining more traction. Lastly, QUIC’s importance increased by choosing it to be the core protocol of the new HTTP/3 standard. The adoption of QUIC results in one of the biggest changes to the web’s protocol stack [6] and spawned the development of various new implementations [7]. 

In order to achieve compatibility with the Internet protocol stack, QUIC was built on top of UDP [3]. While providing transport layer functionality, QUIC is technically an application layer protocol with its own addressing scheme [1]. QUIC’s addressing allows the underlying UDP port and IP address to change, while the connection persists. The QUIC protocol handles the migration of endpoints. To this end, a server has to send UDP datagrams to an unknown endpoint.

As a consequence, QUIC seems particularly vulnerable to address spoofing and request forgery. The specification acknowledges the vulnerabilities and provides first security considerations [3].

In this report, we take a detailed look at version negotiation request forgery attack. To this end, we focus on request forgery attacks initiated by a QUIC client (the attacker). In this scenario, request forgery induces a QUIC server (the victim) to send packets that the attacker controls. The attacker can use the server’s position in the network to gain higher privileges.
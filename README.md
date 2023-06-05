# Project Description
This project contains a complete managed .Net SPF validation, SenderID validation and a dns client and dns server implementation written in C#.

# Donations
If you use this library, please send me your feedback and add a link to this page.
In addition you can donate via [Ko-fi](https://ko-fi.com/alexreinert), [Paypal](https://www.paypal.com/donate/?cmd=_s-xclick&hosted_button_id=4PW43VJ2DZ7R2) or send me a gift from my [Amazon.de wishlist](https://www.amazon.de/gp/registry/wishlist/3NNUQIQO20AAP/ref=nav_wishlist_lists_1)

# Nuget Package
The library is avaible on Nuget, too: [http://nuget.org/packages/ARSoft.Tools.Net](http://nuget.org/packages/ARSoft.Tools.Net)

# API Documentation
A API documentation can be found at [https://docs.ar-soft.de/arsoft.tools.net](https://docs.ar-soft.de/arsoft.tools.net)

# Features
**Parsing and Validating of SPF/SenderID records:**
* RFC 4406 - Sender ID: Authenticating E-Mail
* RFC 4408 - Sender Policy Framework (SPF)
* RFC 7208 - Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1

**Encoding and Decoding:**
* RFC 4648 - The Base16, Base32, and Base64 Data Encodings

**DNS related**
* DNS Client
* Client for Link-Local Multicast Name Resolution
* One-shot-client for Multicast DNS
* (Multithreaded) DNS Server
* Supports synchronous as well as asynchronous resolving
* Discovery of local configured resolver dns servers on Windows and Linux    
* Different resolvers
	* Stub resolver
	* Recursive resolver
	* DNSSEC validating stub resolver
	* DNSSEC validating recursive resolver
* UDP and TCP support
* Full IPv6 support
* DANE validation stream class
* RFC 1034 - Domain Names - Concepts and Facilities
* RFC 1035 - Domain Names – Implementation and Specification
* RFC 1183 - New DNS RR Definitions
* RFC 1348 - DNS NSAP RRs
* RFC 1637 - DNS NSAP Resource Records
* RFC 1706 - DNS NSAP Resource Records
* RFC 1712 - DNS Encoding of Geographical Location
* RFC 1876 - A Means for Expressing Location Information in the Domain Name System
* RFC 1995 - Incremental Zone Transfer
* RFC 1996 - A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
* RFC 2136 - Dynamic Updates in the Domain Name System
* RFC 2163 - Using the Internet DNS to Distribute MIXER Conformant Global Address Mapping (MCGAM)
* RFC 2168 - Resolution of Uniform Resource Identifiers using the Domain Name System
* RFC 2181 - Clarifications to the DNS Specification
* RFC 2230 - Key Exchange Delegation Record for the DNS
* RFC 2308 - Negative Caching of DNS Queries (DNS NCACHE)
* RFC 2535 - Domain Name System Security Extensions
* RFC 2536 - DSA KEYs and SIGs in the Domain Name System
* RFC 2537 - RSA/MD5 KEYs and SIGs in the Domain Name System
* RFC 2539 - Storage of Diffie-Hellman Keys in the Domain Name System
* RFC 2671 - Extension Mechanisms for DNS (EDNS0)
* RFC 2672 - Non-Terminal DNS Name Redirection
* RFC 2673 - Binary Labels in the Domain Name System
* RFC 2782 - A DNS RR for specifying the location of services (DNS SRV)
* RFC 2845 - Secret Key Transaction Authentication for DNS (TSIG)
* RFC 2915 - The Naming Authority Pointer (NAPTR) DNS Resource Record
* RFC 2930 - Secret Key Establishment for DNS (TKEY RR)
* RFC 2931 - DNS Request and Transaction Signatures (SIG(0)s) (Record parsing only)
* RFC 3110 - RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System
* RFC 3123 - A DNS RR Type for Lists of Address Prefixes (APL RR)
* RFC 3225 - Indicating Resolver Support of DNSSEC
* RFC 3226 - DNSSEC and IPv6 A6 aware server/resolver message size requirements
* RFC 3403 - Dynamic Delegation Discovery System (DDDS)
* RFC 3425 - Obsoleting IQUERY
* RFC 3596 - DNS Extensions to Support IP Version 6
* RFC 3597 - Handling of Unknown DNS Resource Record (RR) Types
* RFC 3658 - Delegation Signer (DS) Resource Record (RR)
* RFC 3755 - Legacy Resolver Compatibility for Delegation Signer (DS)
* RFC 3757 - Domain Name System KEY (DNSKEY) Resource Record (RR) Secure Entry Point (SEP) Flag
* RFC 4025 - A Method for Storing IPsec Keying Material in DNS
* RFC 4033 - DNS Security Introduction and Requirements
* RFC 4034 - Resource Records for the DNS Security Extensions
* RFC 4035 - Protocol Modifications for the DNS Security Extensions
* RFC 4255 - Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
* RFC 4398 - Storing Certificates in the Domain Name System (DNS)
* RFC 4431 - The DNSSEC Lookaside Validation (DLV) DNS Resource Record
* RFC 4509 - Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
* RFC 4635 - HMAC SHA TSIG Algorithm Identifiers
* RFC 4701 - A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)
* RFC 4795 - Link-Local Multicast Name Resolution (LLMNR)
* RFC 5001 - DNS Name Server Identifier (NSID) Option
* RFC 5155 - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
* RFC 5205 - Host Identity Protocol (HIP) Domain Name System (DNS) Extension
* RFC 5452 - Measures for Making DNS More Resilient against Forged Answers
* RFC 5702 - Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
* RFC 5864 - DNS SRV Resource Records for AFS
* RFC 5933 - Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC
* RFC 5936 - DNS Zone Transfer Protocol (AXFR)
* RFC 5966 - DNS Transport over TCP - Implementation Requirements
* RFC 6563 - Moving A6 to Historic Status
* RFC 6594 - Use of the SHA-256 Algorithm with RSA, Digital Signature Algorithm (DSA), and Elliptic Curve DSA (ECDSA) in SSHFP Resource Records
* RFC 6605 - Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
* RFC 6672 - DNAME Redirection in the DNS (Record parsing only)
* RFC 6698 - The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
* RFC 6742 - DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)
* RFC 6762 - Multicast DNS (One-shot queries only)
* RFC 6840 - Clarifications and Implementation Notes for DNS Security (DNSSEC)
* RFC 6844 - DNS Certification Authority Authorization (CAA) Resource Record
* RFC 6891 - Extension Mechanisms for DNS (EDNS(0))
* RFC 6975 - Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)
* RFC 7043 - Resource Records for EUI-48 and EUI-64 Addresses in the DNS
* RFC 7129 - Authenticated Denial of Existence in the DNS
* RFC 7208 - Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1
* RFC 7218 - Adding Acronyms to Simplify Conversations about DNS-Based Authentication of Named Entities (DANE)
* RFC 7314 - Extension Mechanisms for DNS (EDNS) EXPIRE Option
* RFC 7344 - Automating DNSSEC Delegation Trust Maintenance
* RFC 7477 - Child-to-Parent Synchronization in DNS
* RFC 7479 - Using Ed25519 in SSHFP Resource Records
* RFC 7553 - The Uniform Resource Identifier (URI) DNS Resource Record
* RFC 7766 - DNS Transport over TCP - Implementation Requirements
* RFC 7828 - The edns-tcp-keepalive EDNS0 Option (Option parsing only)
* RFC 7830 - The EDNS(0) Padding Option
* RFC 7871 - Client Subnet in DNS Queries (Option parsing only)
* RFC 7873 - Domain Name System (DNS) Cookies (Option parsing only)
* RFC 7929 - DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP
* RFC 8005 - Host Identity Protocol (HIP) Domain Name System (DNS) Extension
* RFC 8080 - Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC
* RFC 8162 - Using Secure DNS to Associate Certificates with Domain Names for S/MIME
* RFC 8427 - Representing DNS Messages in JSON
* RFC 8749 - Moving DNSSEC Lookaside Validation (DLV) to Historic Status
* RFC 8777 - DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery
* RFC 8945 - Secret Key Transaction Authentication for DNS (TSIG)
* RFC 9373 - EdDSA Value for IPSECKEY
* draft-vixie-dnsext-dns0x20 - Use of Bit 0x20 in DNS Labels to Improve Transaction Identity
* draft-sekar-dns-llq - DNS Long-Lived Queries
* draft-sekar-dns-ul - Dynamic DNS Update Leases
* draft-cheshire-edns0-owner-option - EDNS0 OWNER Option
* draft-ietf-dnsop-svcb-https - Service binding and parameter specification via the DNS (DNS SVCB and HTTPS RRs) (Record parsing only)

# License
The library is released under [Apache License 2.0](https://github.com/alexreinert/ARSoft.Tools.Net/blob/master/LICENSE)

# Sponsors
* [JetBrains](https://www.jetbrains.com/) supports this project with a free license of ReSharper.

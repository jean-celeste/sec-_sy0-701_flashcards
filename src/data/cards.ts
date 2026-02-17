export type Domain = '1' | '2' | '3' | '4' | '5'

export interface Card {
  id: string
  acronym: string
  definition: string
  domain: Domain
  frequent: boolean
}

type RawCard = [string, string, Domain, boolean]

// Enriched definitions override the plain "spelled out" meaning.
// Keep it short but useful: 1 sentence to short paragraph.
const ENRICHED_DEFS: Record<string, string> = {
  // --- Domain 1 (General Security Concepts) ---
  AAA:
    'Authentication, Authorization, and Accounting — A framework for verifying identity, granting appropriate permissions, and logging actions for auditing and traceability.',
  ABAC:
    'Attribute-based Access Control — Makes access decisions using attributes (user, resource, environment like time/location), enabling fine-grained and flexible policy enforcement.',
  ACL:
    'Access Control List — A list of rules/entries that define which subjects (users/processes) can access which objects (files/resources) and what actions they may perform.',
  AES:
    'Advanced Encryption Standard — A modern symmetric encryption algorithm used to protect data confidentiality (e.g., disk encryption, VPNs, file encryption).',
  'AES-256':
    'Advanced Encryption Standard (256-bit) — AES with a 256-bit key, commonly used where strong confidentiality is required.',
  CA:
    'Certificate Authority — A trusted entity that issues and signs digital certificates so systems can trust identities/keys in a PKI.',
  CIA:
    'Confidentiality, Integrity, Availability — The three core security objectives: prevent unauthorized disclosure, prevent unauthorized changes, and keep systems/data accessible.',
  CRL:
    'Certificate Revocation List — A published list of certificates that are no longer trusted (revoked) before their expiration.',
  CSR:
    'Certificate Signing Request — A request (usually containing a public key and identity info) sent to a CA to obtain a signed certificate.',
  DAC:
    'Discretionary Access Control — The resource owner controls permissions (e.g., file owner decides who can read/write).',
  HMAC:
    'Hashed Message Authentication Code — Uses a shared secret + hash to provide integrity and authenticity (detects tampering and verifies sender knowledge of the secret).',
  MFA:
    'Multifactor Authentication — Uses 2+ factor types (know/have/are) to reduce account takeover risk beyond passwords alone.',
  OCSP:
    'Online Certificate Status Protocol — Checks certificate revocation status in near real-time instead of relying only on CRLs.',
  PKI:
    'Public Key Infrastructure — The people, processes, and technology (CAs, certificates, policies) that enable trusted public-key cryptography at scale.',
  RBAC:
    'Role-based Access Control — Grants permissions based on roles (job functions), simplifying least-privilege management across many users.',
  TLS:
    'Transport Layer Security — A protocol that protects data in transit against eavesdropping and tampering (commonly used for HTTPS).',
  IPSec:
    'Internet Protocol Security — A suite that secures IP traffic (commonly used for site-to-site and remote-access VPNs).',
  AH:
    'Authentication Header — An IPsec component that provides integrity/authentication for IP packets (no encryption).',
  ESP:
    'Encapsulated Security Payload — An IPsec component that can provide confidentiality (encryption) and also integrity/authentication for IP packets.',
  'S/MIME':
    'Secure/Multipurpose Internet Mail Extensions — Uses certificates to digitally sign and encrypt email, providing integrity/authentication and confidentiality.',
  SAML:
    'Security Assertion Markup Language — An XML-based standard for exchanging authentication/authorization assertions, commonly enabling enterprise SSO between an IdP and service provider.',
  TOC:
    'Time-of-check — The moment a system verifies a condition (e.g., permissions) before using a resource; relevant in race condition discussions (TOCTOU).',
  TOU:
    'Time-of-use — The moment a system actually uses a resource after a check; a gap between TOC and TOU can enable TOCTOU attacks.',
  // Note: you can keep separate TOCTOU even if TOC/TOU exist as individual cards
  TOCTOU:
    'Time-of-check to Time-of-use — A race condition where something changes between a security check and the actual use, letting an attacker swap/modify a resource in the gap.',

  // --- Domain 2 (Threats, Vulnerabilities & Mitigations) ---
  CVE:
    'Common Vulnerabilities and Exposures — A standardized identifier for publicly known vulnerabilities, used for tracking and remediation workflows.',
  CVSS:
    'Common Vulnerability Scoring System — A standard scoring method that estimates severity/impact to help prioritize patching.',
  IoC:
    'Indicators of Compromise — Evidence that suggests malicious activity (hashes, IPs, domains, filenames, registry keys, etc.).',
  SQLi:
    'SQL Injection — A web/app attack where malicious SQL is injected via input to read/modify data or bypass authentication.',
  XSS:
    'Cross-site Scripting — Injected script runs in a user’s browser, often used for session theft, redirecting, or malicious actions.',
  CSRF:
    'Cross-site Request Forgery — Tricks an authenticated user’s browser into sending unwanted requests to a site, abusing existing session/cookies.',
  'ATT&CK':
    'MITRE ATT&CK — A knowledge base of real-world adversary tactics and techniques used for threat modeling, detection engineering, and hunting.',
  DDoS:
    'Distributed Denial of Service — Many sources overwhelm a target service/network to degrade availability.',

  // --- Domain 3 (Security Architecture) ---
  CASB:
    'Cloud Access Security Broker — A policy enforcement point between cloud users and cloud services to provide visibility and enforce security controls (e.g., DLP, access, threat protection).',
  SASE:
    'Secure Access Service Edge — A model that converges networking and security as cloud-delivered services for remote users/branches (e.g., secure web access + access control).',
  ICS:
    'Industrial Control Systems — Systems that monitor/control industrial processes; often require strong availability and safety-focused security.',
  SCADA:
    'Supervisory Control and Data Acquisition — A type of ICS used to monitor/control distributed industrial environments (utilities, manufacturing).',
  IDS:
    'Intrusion Detection System — Monitors events/traffic and alerts on signs of possible incidents or policy violations.',
  IPS:
    'Intrusion Prevention System — Like IDS, but can also attempt to stop/block detected malicious activity.',
  NGFW:
    'Next-generation Firewall — Firewall with advanced features like application awareness, IDS/IPS capabilities, and deeper inspection for better threat control.',
  VLAN:
    'Virtual Local Area Network — Logically segments a network to reduce broadcast domains and limit lateral movement.',
  VPN:
    'Virtual Private Network — Encrypted tunnel for secure remote access or site-to-site connectivity over untrusted networks.',
  WAF:
    'Web Application Firewall — Filters HTTP(S) traffic to protect web apps from attacks like SQLi and XSS.',

  // --- Domain 4 (Security Operations) ---
  DLP:
    'Data Loss Prevention — Identifies, monitors, and protects sensitive data in use/in motion/at rest to prevent unauthorized disclosure or exfiltration.',
  SIEM:
    'Security Information and Event Management — Centralizes security logs/events and correlates them into actionable alerts for monitoring, detection, and investigations.',
  SOAR:
    'Security Orchestration, Automation, and Response — Automates and orchestrates incident workflows (triage, enrichment, containment) across multiple tools.',
  EDR:
    'Endpoint Detection and Response — Endpoint-focused monitoring/detection and response capabilities for investigating and containing threats on hosts.',
  XDR:
    'Extended Detection and Response — Correlates telemetry across multiple layers (endpoints, network, cloud, email) for broader detection/response.',
  FIM:
    'File Integrity Management — Detects unauthorized or unexpected file changes by comparing baselines/hashes (useful for tamper detection).',
  HIDS:
    'Host-based Intrusion Detection System — Detects suspicious activity on a single endpoint/host (logs, processes, file changes).',
  NIDS:
    'Network-based Intrusion Detection System — Detects suspicious activity by inspecting network traffic across segments.',
  HIPS:
    'Host-based Intrusion Prevention System — Detects and actively blocks suspicious activity on a host (e.g., stopping a process/action).',
  NIPS:
    'Network-based Intrusion Prevention System — Detects and blocks malicious network traffic inline.',
  SNMP:
    'Simple Network Management Protocol — A protocol for monitoring and managing network devices (collect metrics, query status, receive traps).',
  MSP:
    'Managed Service Provider — Outsourced provider that runs/maintains IT services (helpdesk, infrastructure, monitoring) for clients.',
  MSSP:
    'Managed Security Service Provider — Outsourced provider that runs security operations (monitoring, detection, response, managed tools) for clients.',
  LDAP:
    'Lightweight Directory Access Protocol — Used to query/manage directory services (users/groups), commonly used for centralized authentication/authorization.',
  RADIUS:
    'Remote Authentication Dial-In User Service — Centralized AAA commonly used for network access control (Wi-Fi, VPN, switches).',

  // --- Domain 5 (Security Program Management & Oversight) ---
  ALE:
    'Annualized Loss Expectancy — Expected yearly loss from a risk (often calculated using SLE × ARO) to support risk decisions.',
  ARO:
    'Annualized Rate of Occurrence — How often a loss event is expected to occur per year.',
  SLE:
    'Single Loss Expectancy — Estimated cost/impact of a single occurrence of a risk event.',
  BIA:
    'Business Impact Analysis — Identifies critical processes and the impact of disruption to guide recovery priorities.',
  BCP:
    'Business Continuity Planning — Plans and preparations to keep critical operations running during/after disruptions.',
  DRP:
    'Disaster Recovery Plan — Plans to restore IT services and infrastructure after a major outage/disaster.',
  RPO:
    'Recovery Point Objective — Maximum acceptable data loss measured in time (how far back you can restore).',
  RTO:
    'Recovery Time Objective — Target time to restore service after disruption (maximum acceptable downtime).',
  MTBF:
    'Mean Time Between Failures — Average operational time between failures for repairable systems (reliability metric).',
  MTTF:
    'Mean Time to Failure — Average time until failure for non-repairable components/systems.',
  MTTR:
    'Mean Time to Recover/Repair — Average time to restore service after a failure (maintainability metric).',
}

// Card data: [acronym, definition, domain, isFrequent]
const RAW_CARDS: RawCard[] = [
  // Domain 1: General Security Concepts
  // 1.1/1.2 - Security controls, CIA, AAA, Zero Trust, Physical security, Deception tech
  // 1.3 - Change management
  // 1.4 - Cryptographic solutions
  ['AAA', 'Authentication, Authorization, and Accounting', '1', true],
  ['ACE', 'Access Control Entry', '1', false],
  ['ACK', 'Acknowledge (TCP handshake packet)', '1', false],
  ['ACL', 'Access Control List', '1', true],
  ['AES', 'Advanced Encryption Standard', '1', true],
  ['AES-256', 'Advanced Encryption Standard 256-bit', '1', true],
  ['AH', 'Authentication Header', '1', false],
  ['ASLR', 'Address Space Layout Randomization', '1', false],
  ['AV', 'Antivirus', '1', false],
  ['BASH', 'Bourne Again Shell', '1', false],
  ['CA', 'Certificate Authority', '1', true],
  ['CAPTCHA', 'Completely Automated Public Turing Test to Tell Computers and Humans Apart', '1', false],
  ['CBC', 'Cipher Block Chaining', '1', false],
  ['CCMP', 'Counter Mode/CBC-MAC Protocol', '1', false],
  ['CCTV', 'Closed-circuit Television', '1', false],
  ['CFB', 'Cipher Feedback', '1', false],
  ['CIA', 'Confidentiality, Integrity, Availability', '1', true],
  ['CRC', 'Cyclical Redundancy Check', '1', false],
  ['CRL', 'Certificate Revocation List', '1', true],
  ['CSR', 'Certificate Signing Request', '1', false],
  ['CTM', 'Counter Mode', '1', false],
  ['DES', 'Digital Encryption Standard', '1', false],
  ['DHE', 'Diffie-Hellman Ephemeral', '1', false],
  ['DSA', 'Digital Signature Algorithm', '1', false],
  ['ECC', 'Elliptic Curve Cryptography', '1', false],
  ['ECDHE', 'Elliptic Curve Diffie-Hellman Ephemeral', '1', false],
  ['ECDSA', 'Elliptic Curve Digital Signature Algorithm', '1', false],
  ['EFS', 'Encrypted File System', '1', false],
  ['ESP', 'Encapsulated Security Payload', '1', false],
  ['FDE', 'Full Disk Encryption', '1', false],
  ['GCM', 'Galois Counter Mode', '1', false],
  ['GPG', 'Gnu Privacy Guard', '1', false],
  ['HMAC', 'Hashed Message Authentication Code', '1', false],
  ['HSM', 'Hardware Security Module', '1', false],
  ['HVAC', 'Heating, Ventilation Air Conditioning', '1', false],
  ['IDEA', 'International Data Encryption Algorithm', '1', false],
  ['IKE', 'Internet Key Exchange', '1', false],
  ['IV', 'Initialization Vector', '1', false],
  ['KEK', 'Key Encryption Key', '1', false],
  ['MAC', 'Media Access Control', '1', false],
  ['MAC', 'Message Authentication Code', '1', false],
  ['MD5', 'Message Digest 5', '1', false],
  ['OCSP', 'Online Certificate Status Protocol', '1', false],
  ['P12', 'PKCS #12', '1', false],
  ['PBKDF2', 'Password-based Key Derivation Function 2', '1', false],
  ['PEM', 'Privacy Enhanced Mail', '1', false],
  ['PFS', 'Perfect Forward Secrecy', '1', false],
  ['PGP', 'Pretty Good Privacy', '1', false],
  ['PKCS', 'Public Key Cryptography Standards', '1', false],
  ['PKI', 'Public Key Infrastructure', '1', true],
  ['PSK', 'Pre-shared Key', '1', false],
  ['PTZ', 'Pan-tilt-zoom', '1', false],
  ['RA', 'Recovery Agent', '1', false],
  ['RA', 'Registration Authority', '1', false],
  ['RACE', 'Research and Development in Advanced Communications Technologies in Europe', '1', false],
  ['RC4', 'Rivest Cipher version 4', '1', false],
  ['RIPEMD', 'RACE Integrity Primitives Evaluation Message Digest', '1', false],
  ['RSA', 'Rivest, Shamir, & Adleman', '1', false],
  ['S/MIME', 'Secure/Multipurpose Internet Mail Extensions', '1', false],
  ['SAN', 'Subject Alternative Name', '1', false],
  ['SCEP', 'Simple Certificate Enrollment Protocol', '1', false],
  ['SHA', 'Secure Hashing Algorithm', '1', false],
  ['SSL', 'Secure Sockets Layer', '1', false],
  ['TLS', 'Transport Layer Security', '1', true],
  ['TPM', 'Trusted Platform Module', '1', false],
  ['XOR', 'Exclusive Or', '1', false],

  // Domain 2: Threats, Vulnerabilities & Mitigations
  // 2.1 - Threat actors/motivations
  // 2.2 - Threat vectors/attack surfaces
  // 2.3 - Vulnerability types (incl. race conditions TOC/TOU, memory injection, XSS, SQLi, hardware)
  // 2.4 - Indicators of malicious activity (malware, network attacks, app attacks, cryptographic attacks)
  // 2.5 - Mitigation techniques (HIPS listed here)
  ['APT', 'Advanced Persistent Threat', '2', true],
  ['ARP', 'Address Resolution Protocol', '2', false],
  ['ATT&CK', 'Adversarial Tactics, Techniques, and Common Knowledge', '2', false],
  ['CVE', 'Common Vulnerability Enumeration', '2', true],
  ['CVSS', 'Common Vulnerability Scoring System', '2', true],
  ['DDoS', 'Distributed Denial of Service', '2', true],
  ['DoS', 'Denial of Service', '2', false],
  ['IoC', 'Indicators of Compromise', '2', true],
  ['PUP', 'Potentially Unwanted Program', '2', false],
  ['RAT', 'Remote Access Trojan', '2', false],
  ['RFID', 'Radio Frequency Identifier', '2', false],
  ['SMS', 'Short Message Service', '2', false],
  ['SPIM', 'Spam over Internet Messaging', '2', false],
  ['SQL', 'Structured Query Language', '2', false],
  ['SQLi', 'SQL Injection', '2', true],
  ['STIX', 'Structured Threat Information eXchange', '2', false],
  ['TAXII', 'Trusted Automated eXchange of Indicator Information', '2', false],
  ['TOC', 'Time-of-check', '2', false],
  ['TOU', 'Time-of-use', '2', false],
  ['TTP', 'Tactics, Techniques, and Procedures', '2', false],
  ['USB', 'Universal Serial Bus', '2', false],
  ['USB OTG', 'USB On the Go', '2', false],
  ['XSRF', 'Cross-site Request Forgery', '2', false],
  ['CSRF', 'Cross-site Request Forgery', '2', false],
  ['XSS', 'Cross-site Scripting', '2', true],

  // Domain 3: Security Architecture
  // 3.1 - Architecture models (cloud, IaC, microservices, SDN, IoT, ICS/SCADA, RTOS, embedded, HA)
  // 3.2 - Security principles (firewalls, IDS/IPS placement, VPN, tunneling, SD-WAN, SASE, NAT)
  // 3.3 - Data protection (encryption, tokenization, masking, data types)
  // 3.4 - Resilience and recovery (HA, backups, power/PDU/UPS, RAID, platform diversity)
  ['AI', 'Artificial Intelligence', '3', false],
  ['BGP', 'Border Gateway Protocol', '3', false],
  ['BPDU', 'Bridge Protocol Data Unit', '3', false],
  ['CASB', 'Cloud Access Security Broker', '3', false],
  ['COOP', 'Continuity of Operation Planning', '3', false],
  ['CSP', 'Cloud Service Provider', '3', false],
  ['EAP', 'Extensible Authentication Protocol', '3', false],
  ['ECB', 'Electronic Code Book', '3', false],
  ['GRE', 'Generic Routing Encapsulation', '3', false],
  ['HA', 'High Availability', '3', false],
  ['IaaS', 'Infrastructure as a Service', '3', false],
  ['IaC', 'Infrastructure as Code', '3', false],
  ['ICS', 'Industrial Control Systems', '3', true],
  ['IDF', 'Intermediate Distribution Frame', '3', false],
  ['IDS', 'Intrusion Detection System', '3', true],
  ['IoT', 'Internet of Things', '3', false],
  ['IPSec', 'Internet Protocol Security', '3', false],
  ['IPS', 'Intrusion Prevention System', '3', true],
  ['L2TP', 'Layer 2 Tunneling Protocol', '3', false],
  ['LAN', 'Local Area Network', '3', false],
  ['MAN', 'Metropolitan Area Network', '3', false],
  ['MDF', 'Main Distribution Frame', '3', false],
  ['ML', 'Machine Learning', '3', false],
  ['MPLS', 'Multi-protocol Label Switching', '3', false],
  ['MTU', 'Maximum Transmission Unit', '3', false],
  ['NAT', 'Network Address Translation', '3', false],
  ['NGFW', 'Next-generation Firewall', '3', true],
  ['OT', 'Operational Technology', '3', false],
  ['PaaS', 'Platform as a Service', '3', false],
  ['PAC', 'Proxy Auto Configuration', '3', false],
  ['PAT', 'Port Address Translation', '3', false],
  ['PDU', 'Power Distribution Unit', '3', false],
  ['UPS', 'Uninterruptable Power Supply', '3', false],
  ['PPTP', 'Point-to-Point Tunneling Protocol', '3', false],
  ['RAID', 'Redundant Array of Inexpensive Disks', '3', false],
  ['RTOS', 'Real-time Operating System', '3', false],
  ['SaaS', 'Software as a Service', '3', false],
  ['SAN', 'Storage Area Network', '3', false],
  ['SASE', 'Secure Access Service Edge', '3', true],
  ['SCADA', 'Supervisory Control and Data Acquisition', '3', true],
  ['SD-WAN', 'Software-defined Wide Area Network', '3', true],
  ['SDN', 'Software-defined Networking', '3', false],
  ['SED', 'Self-encrypting Drives', '3', false],
  ['SoC', 'System on Chip', '3', false],
  ['SRTP', 'Secure Real-Time Protocol', '3', false],
  ['TCP/IP', 'Transmission Control Protocol/Internet Protocol', '3', false],
  ['UTM', 'Unified Threat Management', '3', false],
  ['UTP', 'Unshielded Twisted Pair', '3', false],
  ['VDE', 'Virtual Desktop Environment', '3', false],
  ['VDI', 'Virtual Desktop Infrastructure', '3', false],
  ['VLAN', 'Virtual Local Area Network', '3', true],
  ['VLSM', 'Variable Length Subnet Masking', '3', false],
  ['VM', 'Virtual Machine', '3', false],
  ['VPC', 'Virtual Private Cloud', '3', false],
  ['VPN', 'Virtual Private Network', '3', true],
  ['WAF', 'Web Application Firewall', '3', true],
  ['WAP', 'Wireless Access Point', '3', false],
  ['WEP', 'Wired Equivalent Privacy', '3', false],
  ['WIDS', 'Wireless Intrusion Detection System', '3', false],
  ['WIPS', 'Wireless Intrusion Prevention System', '3', false],
  ['WPA', 'Wi-Fi Protected Access', '3', false],
  ['WPS', 'Wi-Fi Protected Setup', '3', false],
  ['WTLS', 'Wireless TLS', '3', false],

  // Domain 4: Security Operations
  // 4.1 - Security techniques (MDM, BYOD/COPE/CYOD, WPA3, RADIUS, wireless, app security, sandboxing)
  // 4.2 - Asset management (acquisition, disposal, sanitization)
  // 4.3 - Vulnerability management (OSINT, CVE/CVSS, SCAP, penetration testing, threat feeds)
  // 4.4 - Security alerting/monitoring (SIEM, DLP, SNMP, NetFlow, vulnerability scanners)
  // 4.5 - Enterprise capabilities (firewall, IDS/IPS, web filter, OS security, email security DMARC/DKIM/SPF, FIM, DLP, NAC, EDR/XDR)
  // 4.6 - Identity and access management (SSO, LDAP, OAuth, SAML, MFA, PAM, TACACS+, CHAP, MSCHAP)
  // 4.7 - Automation/orchestration (APIs, SOAR)
  // 4.8 - Incident response (IR, CIRT, CERT, forensics, chain of custody)
  // 4.9 - Data sources/investigation (logs, PCAP, dashboards)
  ['AIS', 'Automated Indicator Sharing', '4', false],
  ['AP', 'Access Point', '4', false],
  ['API', 'Application Programming Interface', '4', false],
  ['BIOS', 'Basic Input/Output System', '4', false],
  ['BYOD', 'Bring Your Own Device', '4', false],
  ['CERT', 'Computer Emergency Response Team', '4', false],
  ['CHAP', 'Challenge Handshake Authentication Protocol', '4', false],
  ['CIRT', 'Computer Incident Response Team', '4', false],
  ['COPE', 'Corporate Owned, Personally Enabled', '4', false],
  ['CYOD', 'Choose Your Own Device', '4', false],
  ['DBA', 'Database Administrator', '4', false],
  ['DEP', 'Data Execution Prevention', '4', false],
  ['DHCP', 'Dynamic Host Configuration Protocol', '4', false],
  ['DKIM', 'DomainKeys Identified Mail', '4', false],
  ['DLL', 'Dynamic Link Library', '4', false],
  ['DLP', 'Data Loss Prevention', '4', true],
  ['DMARC', 'Domain Message Authentication Reporting and Conformance', '4', false],
  ['DNAT', 'Destination Network Address Translation', '4', false],
  ['DNS', 'Domain Name System', '4', false],
  ['DSL', 'Digital Subscriber Line', '4', false],
  ['EDR', 'Endpoint Detection and Response', '4', true],
  ['ERP', 'Enterprise Resource Planning', '4', false],
  ['FACL', 'File System Access Control List', '4', false],
  ['FIM', 'File Integrity Management', '4', false],
  ['FPGA', 'Field Programmable Gate Array', '4', false],
  ['FRR', 'False Rejection Rate', '4', false],
  ['FTP', 'File Transfer Protocol', '4', false],
  ['FTPS', 'Secured File Transfer Protocol', '4', false],
  ['GPO', 'Group Policy Object', '4', false],
  ['GPS', 'Global Positioning System', '4', false],
  ['GPU', 'Graphics Processing Unit', '4', false],
  ['HDD', 'Hard Disk Drive', '4', false],
  ['HIDS', 'Host-based Intrusion Detection System', '4', true],
  ['HIPS', 'Host-based Intrusion Prevention System', '2', true],
  ['HTML', 'Hypertext Markup Language', '4', false],
  ['HTTP', 'Hypertext Transfer Protocol', '4', false],
  ['HTTPS', 'Hypertext Transfer Protocol Secure', '4', false],
  ['IAM', 'Identity and Access Management', '4', true],
  ['ABAC', 'Attribute-based Access Control', '4', true],
  ['DAC', 'Discretionary Access Control', '4', true],
  ['MAC', 'Mandatory Access Control', '4', true],
  ['MFA', 'Multifactor Authentication', '4', true],
  ['RBAC', 'Role-based Access Control', '4', true],
  ['RBAC', 'Rule-based Access Control', '4', false],
  ['ICMP', 'Internet Control Message Protocol', '4', false],
  ['IdP', 'Identity Provider', '4', false],
  ['IEEE', 'Institute of Electrical and Electronics Engineers', '4', false],
  ['IM', 'Instant Messaging', '4', false],
  ['IMAP', 'Internet Message Access Protocol', '4', false],
  ['IP', 'Internet Protocol', '4', false],
  ['IR', 'Incident Response', '4', false],
  ['IRC', 'Internet Relay Chat', '4', false],
  ['IRP', 'Incident Response Plan', '4', false],
  ['ISO', 'International Standards Organization', '4', false],
  ['ISP', 'Internet Service Provider', '4', false],
  ['KDC', 'Key Distribution Center', '4', false],
  ['LDAP', 'Lightweight Directory Access Protocol', '4', true],
  ['LEAP', 'Lightweight Extensible Authentication Protocol', '4', false],
  ['MaaS', 'Monitoring as a Service', '4', false],
  ['MBR', 'Master Boot Record', '4', false],
  ['MDM', 'Mobile Device Management', '4', true],
  ['MFD', 'Multifunction Device', '4', false],
  ['MFP', 'Multifunction Printer', '4', false],
  ['MMS', 'Multimedia Message Service', '4', false],
  ['HOTP', 'HMAC-based One-time Password', '4', false],
  ['MSCHAP', 'Microsoft Challenge Handshake Authentication Protocol', '4', false],
  ['MSP', 'Managed Service Provider', '4', false],
  ['MSSP', 'Managed Security Service Provider', '4', false],
  ['NAC', 'Network Access Control', '4', true],
  ['NFC', 'Near Field Communication', '4', false],
  ['NIDS', 'Network-based Intrusion Detection System', '4', false],
  ['NIPS', 'Network-based Intrusion Prevention System', '4', false],
  ['NTFS', 'New Technology File System', '4', false],
  ['NTLM', 'New Technology LAN Manager', '4', false],
  ['NTP', 'Network Time Protocol', '4', false],
  ['OAUTH', 'Open Authorization', '4', false],
  ['OID', 'Object Identifier', '4', false],
  ['OS', 'Operating System', '4', false],
  ['OSPF', 'Open Shortest Path First', '4', false],
  ['OTA', 'Over the Air', '4', false],
  ['OVAL', 'Open Vulnerability Assessment Language', '4', false],
  ['P2P', 'Peer to Peer', '4', false],
  ['PAM', 'Privileged Access Management', '4', false],
  ['PAM', 'Pluggable Authentication Modules', '4', false],
  ['PAP', 'Password Authentication Protocol', '4', false],
  ['PBX', 'Private Branch Exchange', '4', false],
  ['PCAP', 'Packet Capture', '4', false],
  ['PEAP', 'Protected Extensible Authentication Protocol', '4', false],
  ['PED', 'Personal Electronic Device', '4', false],
  ['PIV', 'Personal Identity Verification', '4', false],
  ['POP', 'Post Office Protocol', '4', false],
  ['POTS', 'Plain Old Telephone Service', '4', false],
  ['PPP', 'Point-to-Point Protocol', '4', false],
  ['RAD', 'Rapid Application Development', '4', false],
  ['RADIUS', 'Remote Authentication Dial-in User Service', '4', true],
  ['RAS', 'Remote Access Server', '4', false],
  ['RDP', 'Remote Desktop Protocol', '4', false],
  ['RTP', 'Real-time Transport Protocol', '4', false],
  ['SAE', 'Simultaneous Authentication of Equals', '4', false],
  ['SAML', 'Security Assertions Markup Language', '4', true],
  ['SCAP', 'Security Content Automation Protocol', '4', false],
  ['SDK', 'Software Development Kit', '4', false],
  ['SE Linux', 'Security-enhanced Linux', '4', false],
  ['SEH', 'Structured Exception Handler', '4', false],
  ['SFTP', 'Secured File Transfer Protocol', '4', false],
  ['SHTTP', 'Secure Hypertext Transfer Protocol', '4', false],
  ['SIEM', 'Security Information and Event Management', '4', true],
  ['SIM', 'Subscriber Identity Module', '4', false],
  ['SMTP', 'Simple Mail Transfer Protocol', '4', false],
  ['SMTPS', 'Simple Mail Transfer Protocol Secure', '4', false],
  ['SNMP', 'Simple Network Management Protocol', '4', false],
  ['SOAP', 'Simple Object Access Protocol', '4', false],
  ['SOAR', 'Security Orchestration, Automation, Response', '4', true],
  ['SOC', 'Security Operations Center', '4', true],
  ['SPF', 'Sender Policy Framework', '4', false],
  ['SSD', 'Solid State Drive', '4', false],
  ['SSH', 'Secure Shell', '4', false],
  ['SSO', 'Single Sign-on', '4', true],
  ['SWG', 'Secure Web Gateway', '4', false],
  ['TACACS+', 'Terminal Access Controller Access Control System', '4', true],
  ['TGT', 'Ticket Granting Ticket', '4', false],
  ['TKIP', 'Temporal Key Integrity Protocol', '4', false],
  ['TOTP', 'Time-based One-time Password', '4', false],
  ['TSIG', 'Transaction Signature', '4', false],
  ['UAT', 'User Acceptance Testing', '4', false],
  ['UAV', 'Unmanned Aerial Vehicle', '4', false],
  ['UDP', 'User Datagram Protocol', '4', false],
  ['UEFI', 'Unified Extensible Firmware Interface', '4', false],
  ['UEM', 'Unified Endpoint Management', '4', false],
  ['URI', 'Uniform Resource Identifier', '4', false],
  ['URL', 'Universal Resource Locator', '4', false],

  ['VBA', 'Visual Basic', '4', false],
  ['VoIP', 'Voice over IP', '4', false],
  ['VTC', 'Video Teleconferencing', '4', false],
  ['XDR', 'Extended Detection and Response', '4', true],
  ['XML', 'Extensible Markup Language', '4', false],
  ['OSINT', 'Open-source Intelligence', '4', false],

  // Domain 5: Security Program Management & Oversight
  // 5.1 - Governance (AUP, policies incl. BCP/DRP/SDLC, standards, procedures, roles: CIO/CSO/CTO/ISSO)
  // 5.2 - Risk management (SLE, ALE, ARO, BIA, RTO, RPO, MTBF, MTTF, MTTR)
  // 5.3 - Third-party risk (SLA, MOA, MOU, MSA, NDA, BPA, SOW/WO)
  // 5.4 - Compliance (GDPR, PCI DSS, PII, PHI, privacy, DPO)
  // 5.5 - Audits and assessments (pen testing)
  // 5.6 - Security awareness
  ['ALE', 'Annualized Loss Expectancy', '5', true],
  ['ARO', 'Annualized Rate of Occurrence', '5', true],
  ['AUP', 'Acceptable Use Policy', '5', false],
  ['BCP', 'Business Continuity Planning', '5', true],
  ['BIA', 'Business Impact Analysis', '5', true],
  ['BPA', 'Business Partners Agreement', '5', false],
  ['CAR', 'Corrective Action Report', '5', false],
  ['CIO', 'Chief Information Officer', '5', false],
  ['CMS', 'Content Management System', '5', false],
  ['CP', 'Contingency Planning', '5', false],
  ['CSO', 'Chief Security Officer', '5', false],
  ['CTO', 'Chief Technology Officer', '5', false],
  ['DPO', 'Data Privacy Officer', '5', false],
  ['DRP', 'Disaster Recovery Plan', '5', false],
  ['ESN', 'Electronic Serial Number', '5', false],
  ['GDPR', 'General Data Protection Regulation', '5', false],
  ['ISSO', 'Information Systems Security Officer', '5', false],
  ['MOA', 'Memorandum of Agreement', '5', true],
  ['MOU', 'Memorandum of Understanding', '5', true],
  ['MSA', 'Master Service Agreement', '5', false],
  ['MTBF', 'Mean Time Between Failures', '5', true],
  ['MTTF', 'Mean Time to Failure', '5', false],
  ['MTTR', 'Mean Time to Recover', '5', true],
  ['NDA', 'Non-disclosure Agreement', '5', true],
  ['NIST', 'National Institute of Standards & Technology', '5', false],
  ['PCI DSS', 'Payment Card Industry Data Security Standard', '5', false],
  ['PHI', 'Personal Health Information', '5', false],
  ['PII', 'Personally Identifiable Information', '5', false],
  ['ROI', 'Return on Investment', '5', false],
  ['RPO', 'Recovery Point Objective', '5', true],
  ['RTO', 'Recovery Time Objective', '5', true],
  ['SDLC', 'Software Development Lifecycle', '5', false],
  ['SDLM', 'Software Development Lifecycle Methodology', '5', false],
  ['SLA', 'Service-level Agreement', '5', true],
  ['SLE', 'Single Loss Expectancy', '5', true],
  ['SOW', 'Statement of Work', '5', false],
  ['WO', 'Work Order', '5', false],
]

export const CARDS: Card[] = RAW_CARDS.map(([acronym, definition, domain, frequent], index) => {
  const enriched = ENRICHED_DEFS[acronym]
  return {
    id: `${acronym}-${domain}-${index}`,
    acronym,
    // Prefer enriched meaning; fall back to original.
    definition: enriched ? `${definition} — ${enriched}` : definition,
    domain,
    frequent,
  }
})


---
title: BREEZE COMET Targets Brazilian Financial Systems
slug: 2026-09-breeze-comet
description: The financially motivated actor BREEZE COMET exploits payment systems and banking software in Brazil using a custom malware suite, including LDAP brute-forcing tools and specialized network tunneling, to facilitate fraudulent transfers.
date: "2026-09-01T05:56:33Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - BREEZE COMET
tags:
  - financial-fraud
  - malware
  - persistence
  - exfiltration
vendors:
  - JBoss
products:
  - JBoss AS
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: GTIG observed BREEZE COMET using compromised Brazilian small government websites to stage RMM tools, infostealers disguised as legitimate tax or receipt documents (e.g., ComprovantePDF.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: BREEZE COMET then used these compromised government websites to facilitate social engineering operations for initial access, and as C2 endpoints... XWORM set to persist via automated startup shortcut modifications.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1110.003
    technique_name: Password Spraying
    evidence: In early compromises, Mandiant observed this threat actor use password spraying as well as voice calls impersonating IT support teams
    confidence_band: high
iocs:
  - type: domain
    value: dontpad.com
ioc_counts:
  domain: 1
---

BREEZE COMET (formerly UNC5669) is a financially motivated threat actor specializing in manipulating Brazilian financial and payment systems, including Pix, STR, and Boleto. Since 2024, the group has targeted banks, retailers, and fintech providers to conduct fraudulent transfers. Their operations are characterized by a sophisticated, custom malware suite including REALBREEZE for LDAP brute-forcing, COBALTSPIN for evasive SOCKS5 proxy tunneling, and LIGHTPAINT for VPN-based persistence. 

The actor demonstrates high operational maturity, utilizing social engineering, password spraying, and exploitation of JBoss AS servers for initial access. They specifically target CI/CD pipelines and cloud environments to harvest API keys and administrative mTLS credentials. Google Threat Intelligence Group has observed the group leveraging generative AI for malware development and expanding their infrastructure to municipal domains in Africa and Latin America, suggesting an intent to scale operations beyond Brazil.

## Attack Chain

1. Initial access is gained via password spraying, voice phishing (impersonation of IT), or exploitation of JBoss AS vulnerabilities.
2. RMM tools or infostealers (e.g., XWORM) are staged on compromised government websites and executed on victim endpoints.
3. Attackers perform internal reconnaissance using tools like ADRecon and custom LDAP brute-forcing utilities (REALBREEZE) to identify privileged accounts.
4. CI/CD pipelines are mined for hard-coded credentials, API keys, and cloud access tokens to escalate privileges within cloud environments.
5. Lateral movement is performed via hijacked service accounts using RDP and SMB, often utilizing custom Rust-based routing malware (COBALTSPIN) for SOCKS5 tunneling.
6. Persistence is maintained using LIGHTPAINT, which installs a legitimate VPN (SoftEther), modifies Windows Defender Firewall rules, and clears specific event logs to hide the connection.
7. Search scripts query host files and environment variables for financial keywords (e.g., 'boleto', 'pix', 'remessa') to locate mTLS credentials.
8. Stolen credentials are used to authenticate against financial API infrastructure to initiate fraudulent transfers.

## Impact

BREEZE COMET’s activity results in significant financial loss through fraudulent transfers executed via compromised payment systems. The group targets critical financial infrastructure and retail networks, affecting financial services, retail, and eCommerce sectors. If successful, the actor achieves sustained, persistent access to internal financial networks, allowing for long-term credential theft and repeated unauthorized transactions.

## Recommendation

1. Audit and restrict access to CI/CD environments; move secrets from hard-coded variables to secure vaulting solutions.
2. Implement strict mTLS validation and monitor for anomalous outbound traffic from financial API integration nodes.
3. Deploy detection for unauthorized VPN-based connections by monitoring Windows Defender Firewall rule modifications and VPN plugin service activity.
4. Monitor for the execution of reconnaissance utilities like ADRecon and LDAP-querying scripts in high-privilege environments.
5. Proactively hunt for indicators of COBALTSPIN tunnels by analyzing network traffic for long-lived, outbound WebSocket connections to unauthorized endpoints.
6. Configure logging for the 'Windows Networking Vpn Plugin Platform' and alert on instances where these logs are cleared.

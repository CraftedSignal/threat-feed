---
title: Gunra Ransomware Exploitation of Fortinet and Schneider Electric Vulnerabilities
slug: 2026-08-gunra-ransomware
description: The Gunra ransomware group is leveraging CVE-2024-5559 and CVE-2025-24472 to gain initial access and execute a double-extortion campaign against global critical infrastructure.
date: "2026-08-11T11:28:56Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Gunra
cpes:
  - cpe:2.3:o:schneider-electric:powerlogic_p5_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
vendors:
  - Schneider Electric
  - Fortinet
  - AnySign4PC
products:
  - PowerLogic P5
  - FortiOS
  - FortiProxy
  - AnySign4PC
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attacks deploying the ransomware have leveraged security flaws in internet-facing Schneider Electric PowerLogic P5 (CVE-2024-5559) and Fortinet FortiOS and FortiProxy (CVE-2025-24472) appliances to obtain initial access.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Attack chains are known to leverage Impacket libraries psexec.py and smbclient.py for lateral movement using the Server Message Block (SMB) protocol.
    confidence_band: high
cves:
  - id: CVE-2024-5559
    cvss: 6.1
    epss: 0.00164
  - id: CVE-2025-24472
    cvss: 8.1
    epss: 0.03342
references:
  - https://thehackernews.com/2026/08/gunra-ransomware-exploits-fortinet-and.html
---

Gunra is a ransomware operation that has evolved since April 2025 to target critical infrastructure sectors globally, including government, finance, and healthcare. The group operates a Ransomware-as-a-Service (RaaS) model and is known for double extortion, combining data exfiltration with encryption. Recent activity involves the exploitation of internet-facing vulnerabilities in Schneider Electric PowerLogic P5 (CVE-2024-5559) and Fortinet FortiOS/FortiProxy (CVE-2025-24472) to obtain initial network access. 

The group demonstrates high technical proficiency, including manipulating VDI and SSL-VPN authentication flows to bypass MFA and harvesting sensitive configuration data from enterprise environments. They use a mix of native tools, Impacket libraries, and custom payloads to facilitate lateral movement, credential dumping, and mass exfiltration of business data. Despite a identified cryptographic weakness in Linux variants, the group remains a significant threat due to their aggressive recruiting of initial access brokers and ability to deploy ransomware rapidly against database servers and NAS systems.

## Attack Chain

1. Initial access is established by exploiting known vulnerabilities (CVE-2024-5559 or CVE-2025-24472) in internet-facing Schneider Electric or Fortinet appliances.
2. Attackers gain administrative access to SSL-VPN or VDI portals, often by manipulating authentication files to enable bypasses or using default credentials.
3. Persistent access is maintained by downloading OpenSSH and configuring backdoors on compromised appliances.
4. Internal reconnaissance is conducted using compromised credentials to identify domain controllers and enterprise server infrastructure.
5. Lateral movement is performed using Impacket tools such as psexec.py and smbclient.py, while secretsdump.py is utilized to extract credentials from NTDS files.
6. Data is exfiltrated from Microsoft OneDrive, SharePoint, and VDI environments using a custom executable named 'main.exe' or via large compressed archives to MEGA.
7. Backup and recovery infrastructure is identified and systematically deleted to prevent restoration.
8. Final objective is achieved by deploying ransomware payloads to encrypt database servers, NAS systems, and critical enterprise assets.

## Impact

Gunra has successfully targeted at least 51 victims across South Korea, Brazil, Spain, Thailand, and Hong Kong since April 2025. The attack impacts critical sectors by causing severe operational disruption and potential long-term data loss through unauthorized disclosure. Organizations that refuse to pay the ransom face the permanent leakage of sensitive business data on public forums, impacting regulatory compliance and reputation.

## Recommendation

* Patch CVE-2024-5559 on all internet-facing Schneider Electric PowerLogic P5 devices immediately.
* Patch CVE-2025-24472 on all Fortinet FortiOS and FortiProxy appliances to prevent initial exploitation.
* Implement strict network segmentation and monitor for unauthorized lateral movement involving Impacket tools and SMB traffic.
* Audit VDI and SSL-VPN authentication portals for modified configuration files or anomalous MFA bypass logic.
* Deploy immutable, off-site backups to ensure business continuity following potential ransomware deployment.

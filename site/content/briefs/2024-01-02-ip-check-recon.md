---
brief_id: brief-2024-01-02-ip-check-recon
event_id: brief-2024-01-02-ip-check-recon
revision: 2
activity_at: "2024-01-02T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:4e1c3b7dcfc0c672f61454a2a3f1b8357e1effdff94b8cb14e7a2cd733cc6872
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Malware Gathering Victim Network Information via Public IP Check Services
slug: 2024-01-02-ip-check-recon
description: Malware and related tools use public IP check services to enumerate victim external IP addresses for reconnaissance and situational awareness.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
actors:
  - Multiple malware families
exploitation_evidence:
  status: unknown
tags:
  - reconnaissance
  - malware
  - windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: Gather Victim Network Information
references:
  - https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/
iocs:
  - type: domain
    value: wtfismyip.com
  - type: domain
    value: ipinfo.io
  - type: domain
    value: api.ipify.org
  - type: domain
    value: icanhazip.com
  - type: domain
    value: ip.anysrc.com
  - type: domain
    value: api.ip.sb
  - type: domain
    value: ident.me
  - type: domain
    value: www.myexternalip.com
  - type: domain
    value: zen.spamhaus.org
  - type: domain
    value: cbl.abuseat.org
  - type: domain
    value: b.barracudacentral.org
  - type: domain
    value: dnsbl-1.uceprotect.net
  - type: domain
    value: spam.dnsbl.sorbs.net
  - type: domain
    value: iplogger.org
  - type: domain
    value: ip-api.com
  - type: domain
    value: ipwho.is
  - type: domain
    value: ifconfig.me
  - type: domain
    value: myip.com
  - type: domain
    value: ipstack.com
  - type: domain
    value: myexternalip.com
  - type: domain
    value: ip-api.io
  - type: domain
    value: trackip.net
  - type: domain
    value: ipgeolocation.io
  - type: domain
    value: ipfind.io
  - type: domain
    value: freegeoip.app
  - type: domain
    value: ipv4bot.whatismyipaddress.com
ioc_counts:
  domain: 26
rules:
  - title: Detect Process Querying IP Check Services via DNS
    description: Detects processes making DNS queries to known IP check services to determine the external IP address.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1590.005
    data_sources:
      - dns_query
      - windows
  - title: Detect Svchost Querying IP Check Services via DNS
    description: Detects svchost.exe making DNS queries to known IP check services to determine the external IP address.
    platform: sigma
    severity: high
    tactics:
      - reconnaissance
    techniques:
      - T1590.005
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This brief focuses on the technique of malware and related tools querying public IP check services to identify the external IP address of a compromised host. This activity is typically performed early in the infection lifecycle to give the attacker situational awareness of the victim's network. This information can be used to tailor attacks, identify the victim's geographic location, and potentially identify the organization to which the victim belongs. This technique is used by a wide variety of malware families, including Trickbot, Azorult, and many others, to perform reconnaissance on the compromised host. This behavior is identified using Sysmon EventCode 22 logs, specifically monitoring DNS queries to services.

## Attack Chain

1. A user unknowingly executes a malicious executable (e.g., via drive-by download or opening a malicious attachment).
2. The malicious executable starts on the host, typically with user-level privileges.
3. The malware initiates a DNS query to a known IP check service (e.g., `wtfismyip.com`, `ipinfo.io`, `icanhazip.com`) using the `QueryName` field in Sysmon Event ID 22.
4. The DNS query is resolved, and the malware receives the external IP address of the compromised host.
5. The malware may then use this IP address for further reconnaissance, such as geolocation lookups or identifying the organization to which the IP address belongs.
6. The gathered information is sent back to the attacker-controlled command-and-control (C2) server.
7. The attacker uses the gathered information to tailor subsequent attacks, such as lateral movement or data exfiltration.

## Impact

Successful execution of this reconnaissance technique provides attackers with valuable information about the victim's network. This information can be used to tailor subsequent attacks, increasing the likelihood of success. In the case of ransomware attacks, knowing the victim's organization can allow the attacker to demand a larger ransom. The use of IP check services has been observed across a diverse range of malware families and impacts organizations across all sectors.

## Recommendation

*   Enable Sysmon Event ID 22 logging to capture DNS query events.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Block the C2 domains listed in the IOC table at the DNS resolver.
*   Investigate any unusual process making DNS queries to IP check services, as highlighted by the detection rules.

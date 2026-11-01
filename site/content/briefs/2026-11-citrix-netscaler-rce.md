---
brief_id: brief-2026-11-01-citrix-netscaler-rce
event_id: brief-2026-11-01-citrix-netscaler-rce
revision: 1
activity_at: "2026-11-01T10:58:14Z"
title: 'Citrix NetScaler: AAA Service pre-authentication heap overflow (CVE-2026-8452)'
slug: 2026-11-citrix-netscaler-rce
description: CVE-2026-8452 is a critical pre-authentication heap overflow in the Citrix NetScaler AAA service, reachable when SAML is configured, allowing for remote code execution via publicly available exploit code.
date: "2026-11-01T10:58:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:fips:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:ndcpp:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:-:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:14.1-66.68:*:*:*:fips:*:*:*
  - cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*
tags:
  - cve-2026-8452
  - remote-code-execution
  - heap-overflow
  - citrix
  - network
vendors:
  - Citrix
products:
  - NetScaler ADC (< 13.1-37.272, 13.1-63.18, 14.1-72.61, 14.1-66.68)
  - NetScaler Gateway (< 13.1-63.18, 14.1-72.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Pre-auth heap overflow to RCE in Citrix NetScaler via AAA service, exploited as CVE-2026-8452.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: triggering jmp rax to 0x112d30180 ... webshell will be at https://172.16.5.12:9443/vpn/theme/x.php
    confidence_band: high
cves:
  - id: CVE-2026-8452
    cvss: 9.8
    epss: 0.01011
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WATCHTOWRLABS-WATCHTOWR-VS-CITRIX-NETSCALER-PREAUTH-RCE-CVE-2026-8452
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WATCHTOWRLABS-WATCHTOWR-VS-CITRIX-NETSCALER-PREAUTH-RCE-CVE-2026-8452&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Citrix NetScaler ADC and Gateway to 13.1-63.18 or 14.1-72.61.
      owner: IT Operations
      due: 24h
      evidence: Vendor guidance via Sploitus report.
  hunt_leads:
    - lead: Identify unexpected file creation or unauthorized PHP scripts within /vpn/theme/ directories.
      technique_id: T1505.003
      data_needed:
        - File system integrity logs
        - Web server access/error logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit writes a webshell to https://[target]/vpn/theme/x.php.
  mitigation_plan:
    - priority: immediate
      action: Disable SAML authentication service if not strictly required, or restrict access to AAA service via IP allowlisting.
      owner: IT Operations
      addresses: CVE-2026-8452
      evidence: Vulnerability is reachable when SAML is configured.
---

CVE-2026-8452 is a memory corruption vulnerability in the Citrix NetScaler AAA service. The flaw is a heap overflow that allows for unauthenticated remote code execution. The vulnerability is specifically reachable when the NetScaler appliance is configured to use SAML as either a Service Provider (SP) or an Identity Provider (IdP). A working exploit has been publicly disclosed, including a tool that deploys a webshell to the appliance.

## Attack Chain
1. Attacker identifies an internet-facing Citrix NetScaler appliance configured with SAML.
2. Attacker sends a crafted request to the AAA service endpoint to trigger a heap overflow.
3. Memory corruption allows for controlled execution flow redirection.
4. Attacker leverages the heap overflow to execute arbitrary shellcode.
5. Shellcode writes a PHP webshell to a predictable location (e.g., /vpn/theme/x.php).
6. Attacker interacts with the webshell to execute arbitrary system commands with root privileges.

## Impact
Successful exploitation allows an unauthenticated attacker to execute arbitrary code with root privileges on the affected NetScaler appliance, potentially leading to full compromise of the device and persistent access.

## Recommendation
- Immediately patch all Citrix NetScaler ADC and Gateway instances to the versions identified by the vendor as non-vulnerable: NetScaler ADC/Gateway 13.1 (>= 13.1-63.18) and 14.1 (>= 14.1-72.61).
- Review network access controls to ensure the AAA service is not unnecessarily exposed to untrusted networks.
- Audit the web directory paths mentioned in the exploit (e.g., /vpn/theme/) for the presence of unauthorized files or scripts.

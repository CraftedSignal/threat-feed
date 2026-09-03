---
title: Detection of DNSExfiltrator PowerShell Activity
slug: 2026-09-dnsexfiltration
description: Adversaries utilize the DNSExfiltrator tool to tunnel file data through covert DNS requests, bypassing traditional network egress filtering.
date: "2026-09-03T13:40:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - exfiltration
  - powershell
  - detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: DNSExfiltrator allows for transferring (exfiltrate) a file over a DNS request covert channel
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_dnsexfiltration.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1048/T1048.md#atomic-test-3---dnsexfiltration-doh
  - https://github.com/Arno0x/DNSExfiltrator
rules:
  - title: Detect DNSExfiltrator PowerShell Usage
    description: Detects the use of DNSExfiltrator commandlets or specific parameter combinations indicative of covert DNS exfiltration
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1048
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging across domain
      owner: IT Operations
      due: 48h
      evidence: Required for detection of tool invocation
  hunt_leads:
    - lead: Search for DNS queries containing long, high-entropy subdomains
      technique_id: T1048
      data_needed:
        - DNS query logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: DNS exfiltration inherently relies on high-entropy DNS request structures
---

DNSExfiltrator is a post-exploitation utility used by threat actors to exfiltrate sensitive files from a compromised host by embedding data within DNS queries. The tool leverages DNS as a covert communication channel, allowing exfiltration to occur even in highly restricted network environments where direct internet access is blocked. It supports multiple encoding schemes and DNS-over-HTTPS (DoH) for obfuscation, making it difficult to detect via standard perimeter firewalls. By breaking files into small chunks and sending them as subdomains in iterative DNS requests, the tool reconstructs the data on an attacker-controlled authoritative name server. Monitoring PowerShell Script Block Logging is essential for detecting the invocation of this tool before exfiltration traffic occurs.

## Attack Chain

1. Initial access is established through a previously compromised endpoint.
2. PowerShell is executed to load the DNSExfiltrator framework.
3. The operator specifies the target file path using the `-i` parameter.
4. The operator defines the target malicious DNS domain using the `-d` parameter.
5. The tool configures exfiltration parameters, such as delay and chunk size, via the `-p` and `-t` flags.
6. The operator optionally specifies DNS-over-HTTPS (DoH) redirection using the `-doh` parameter.
7. DNSExfiltrator chunks the file data and initiates recursive DNS queries.
8. Data is exfiltrated to the attacker's listener, where it is reassembled.

## Impact

Successful deployment of DNSExfiltrator results in the stealthy exfiltration of sensitive organizational data, including configuration files, credentials, or intellectual property. Because this technique relies on DNS, it effectively circumvents traditional DLP and proxy-based egress controls, leading to high-impact data loss that may remain undetected for extended periods.

## Recommendation

1. Enable Windows PowerShell Script Block Logging (Event ID 4104) across all endpoints to capture the command-line arguments used by this tool.
2. Deploy the provided Sigma rule to your SIEM to monitor for 'Invoke-DNSExfiltrator' or associated command-line parameters.
3. Review DNS query logs for anomalous spikes in traffic directed to unknown or high-entropy subdomains, which may indicate active exfiltration.

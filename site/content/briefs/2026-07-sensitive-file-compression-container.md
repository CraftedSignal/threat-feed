---
title: Sensitive File Compression Detected in Linux Containers for Credential Access
slug: 2026-07-sensitive-file-compression-container
description: Elastic Defend for Containers detects the use of compression utilities like tar or zip within Linux containers to collect sensitive files such as SSH keys, AWS credentials, or system configurations, indicating potential credential access and data collection attempts by adversaries.
date: "2026-07-29T12:32:00Z"
lastmod: "2026-07-29T12:47:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - linux
  - credential-access
  - data-collection
  - threat-detection
  - discovery
  - reconnaissance
  - network-scanning
  - network-sniffing
  - elastic-defend
vendors:
  - Elastic
products:
  - Defend for Containers
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials and system configurations
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials and system configurations inside a container.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Network utilities like nc, nmap, dig, tcpdump, ngrep, telnet, mitmproxy, zmap can be used for malicious purposes such as network reconnaissance, monitoring, or exploitation.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries exploit network tools within containers for reconnaissance or lateral movement, leveraging utilities like `nc` or `nmap` to map networks or intercept traffic.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Network utilities like nc, nmap, dig, tcpdump, ngrep, telnet, mitmproxy, zmap can be used for malicious purposes such as network reconnaissance, monitoring, or exploitation.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1040
    technique_name: Network Sniffing
    evidence: Network utilities like nc, nmap, dig, tcpdump, ngrep, telnet, mitmproxy, zmap can be used for malicious purposes such as network reconnaissance, monitoring, or exploitation.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/credential_access_collection_sensitive_files_compression_inside_a_container.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_kubelet_certificate_file_access.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_suspicious_network_tool_launched_inside_a_container.toml
iocs:
  - type: filepath
    value: /var/lib/kubelet/pki/
ioc_counts:
  filepath: 1
rules:
  - title: Sensitive File Compression Detected via Defend for Containers
    description: Detects the use of compression utilities to collect known files containing sensitive information, such as credentials and system configurations, inside a Linux container.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1005
      - T1552
      - T1552.001
      - T1560
      - T1560.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Network Tool Launch in Linux Containers
    description: Detects commonly abused network utilities (e.g., nc, nmap, tcpdump) running inside Linux containers, which can be used for malicious purposes such as reconnaissance, monitoring, or exploitation. This rule covers direct execution and invocation via common shells.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - credential_access
      - discovery
      - reconnaissance
    techniques:
      - T1040
      - T1046
      - T1105
      - T1595
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-07-29T12:41:35Z"
    level: L1
    summary: new IOCs
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_kubelet_certificate_file_access.toml
  - at: "2026-07-29T12:47:47Z"
    level: L1
    summary: 'added detection rule: Detect Suspicious Network Tool Launch in Linux Containers'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_suspicious_network_tool_launched_inside_a_container.toml
---

This brief describes a detection mechanism implemented by Elastic Defend for Containers aimed at identifying credential access and collection activities within Linux container environments. Adversaries often exploit compromised containers to locate and gather sensitive information, including cloud provider credentials (AWS, Azure, GCP), SSH keys, Docker configurations, and system configuration files (e.g., `/etc/passwd`, `/etc/shadow`). The detection focuses on the use of common compression utilities such as `zip`, `tar`, `gzip`, `hdiutil`, `7z`, `rar`, `7zip`, or `p7zip`, either executed directly or via shell processes (`bash`, `sh`, `zsh`), when their command-line arguments target known sensitive file paths. This activity signals an attacker's attempt to stage data for exfiltration after gaining access to a container. The detection was reintroduced with Elastic Stack version 9.3.0.

## Attack Chain

1. **Initial Access**: An adversary gains unauthorized access to a Linux container instance, potentially through a vulnerable application, misconfiguration, or compromised credentials for a management interface.
2. **Discovery**: Within the compromised container, the adversary enumerates the file system to locate sensitive files containing credentials, configuration data, or other valuable information.
3. **Collection - Locate Sensitive Data**: The attacker specifically targets files and directories known to store credentials or critical system configurations, such as `~/.ssh/`, `~/.aws/`, `~/.docker/`, `/etc/passwd`, `/etc/shadow`, or cloud-specific credential files (e.g., `application_default_credentials.json`).
4. **Collection - Archive Sensitive Data**: To consolidate and prepare for exfiltration, the adversary executes a compression utility (e.g., `tar`, `zip`, `gzip`, `7z`) directly or via a shell script, specifying the previously identified sensitive files as input.
5. **Staging**: The compression utility creates an archive file containing the collected sensitive data, typically in a temporary or accessible location within the container's file system, ready for the next phase.
6. **Exfiltration (Implied)**: The adversary then moves the compressed archive out of the container environment to an external command and control server or storage location, completing the data theft objective.

## Impact

Successful sensitive file compression and subsequent exfiltration from a compromised container can lead to significant data breaches and further attacks. Attackers can leverage stolen SSH keys, cloud provider API credentials, or Docker configuration files to gain access to other systems, cloud resources, or orchestrate lateral movement within the victim's infrastructure. This can result in unauthorized cloud resource provisioning, data theft from cloud storage, disruption of services, and a broader compromise of the organization's environment, potentially incurring severe financial, reputational, and regulatory consequences.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM to detect suspicious compression activities targeting sensitive files within Linux containers.
* Ensure Elastic Defend for Containers is properly configured and enabled on all Linux container hosts to collect process execution logs.
* Review the investigation steps outlined in this brief for any triggered alerts to identify the container, process, and files involved.
* Isolate affected containers immediately upon detection to prevent further data exfiltration or unauthorized access, as recommended in the remediation section.
* Rotate any credentials (SSH keys, cloud API keys) potentially exposed by the collected sensitive files.

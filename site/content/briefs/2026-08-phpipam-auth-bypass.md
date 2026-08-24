---
title: Authorization Bypass in phpIPAM Temporary Share Feature
slug: 2026-08-phpipam-auth-bypass
description: phpIPAM versions up to 1.8.1 contain an authorization vulnerability allowing an unauthenticated attacker with a temporary share token to enumerate and exfiltrate sensitive network inventory data.
date: "2026-08-18T00:51:38Z"
lastmod: "2026-08-24T16:02:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - phpIPAM
products:
  - phpIPAM (1.8.1)
  - phpIPAM (< 1.8.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An unauthenticated party holding any valid, non-expired temporary share URL can enumerate the subnetId parameter to read every IP address record across all sections and subnets.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The vulnerability allows attackers to use the numeric database row identifier as an API token to read, write, and delete all IP address management records.
    confidence_band: high
cves:
  - id: CVE-2026-75105
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75105
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67602
rules:
  - title: Detect CVE-2026-75105 Exploitation - Unauthorized Subnet ID Enumeration
    description: Detects potential exploitation of CVE-2026-75105 where an attacker manipulates the subnetId parameter in the temporary share feature to access unauthorized subnets.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade phpIPAM to a patched version.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-75105
  hunt_leads:
    - lead: High volume of requests to temp_share endpoint from single source
      technique_id: T1592
      data_needed:
        - Web server logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker enumerates subnetId parameter
  mitigation_plan:
    - priority: immediate
      action: Restrict access to temporary share URLs to authorized IP ranges.
      owner: IT Operations
      addresses: CVE-2026-75105
      evidence: Vulnerability allows unauthenticated access
updates:
  - at: "2026-08-24T16:02:08Z"
    level: L2
    summary: added coverage for phpIPAM (< 1.8.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67602
---

phpIPAM versions through 1.8.1 contain an authorization vulnerability (CVE-2026-75105) within the temporary share feature. The application fails to verify that a requested IP address belongs to the specific subnet associated with a valid temporary share token. In the files 'app/temp_share/index.php' and 'app/temp_share/address.php', the 'subnetId' parameter is used directly as a database primary key when the share type is set to 'subnets'. This lack of validation allows an unauthenticated user, in possession of any valid, non-expired temporary share URL, to manipulate the 'subnetId' parameter. By iterating through potential IDs, an attacker can enumerate and retrieve IP address records across all sections and subnets. The resulting exposure includes sensitive information such as hostnames, DNS names, MAC addresses, owner details, and potentially notes containing credentials or network configuration details, which poses a significant risk to internal network security.

## Impact

Successful exploitation allows unauthorized access to comprehensive network inventory data. This data can be used by an attacker to perform reconnaissance on internal infrastructure, identify high-value targets, and potentially gain access to credentials stored within IPAM notes. The vulnerability affects all deployments of phpIPAM up to version 1.8.1.

## Recommendation

- Upgrade to a patched version of phpIPAM that correctly validates subnet ownership for temporary shares.
- Audit existing temporary shares for abuse or exposure of sensitive notes.
- Implement access logging to monitor for anomalous traversal of 'subnetId' parameters in the temporary share module.
- Restrict access to the phpIPAM management interface to trusted internal networks or via VPN to reduce exposure to unauthorized entities.

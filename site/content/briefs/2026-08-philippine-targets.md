---
title: Chinese-Speaking Operator Targets Philippine Nuclear and Naval Infrastructure
slug: 2026-08-philippine-targets
description: A suspected Chinese-speaking operator is targeting Philippine governmental and defense entities by exploiting ownCloud and LiteSpeed Cache vulnerabilities to exfiltrate personnel data and deploy loaders.
date: "2026-08-26T14:16:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:owncloud:owncloud_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:litespeedtech:litespeed_cache:*:*:*:*:*:wordpress:*:*
tags:
  - espionage
  - web-exploitation
  - data-exfiltration
vendors:
  - ownCloud
  - LiteSpeed
  - ZKTeco
products:
  - ownCloud
  - LiteSpeed Cache
  - BioTime
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The operator inserted randomized sleep intervals to avoid volumetric detection on outbound traffic and leveraged known vulnerabilities in ownCloud and LiteSpeed Cache.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: Naval contractor hit via... XML-RPC brute force with rockyou.txt.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 192 MB ZKTeco BioTime attendance/personnel SQL dump recovered.
    confidence_band: high
cves:
  - id: CVE-2023-49105
    cvss: 9.8
    epss: 0.11074
  - id: CVE-2024-28000
    cvss: 9.8
    epss: 0.68266
references:
  - https://hunt.io/blog/chinese-speaking-operator-philippine-nuclear-naval-contractor
  - https://www.reddit.com/r/blueteamsec/comments/1vyy37m/philippine_nuclear_agency_and_naval_contractor/
rules:
  - title: Detect CVE-2023-49105 WebDAV Enumeration
    description: 'Detects PROPFIND requests with Depth: 1 headers indicative of ownCloud WebDAV reconnaissance.'
    platform: sigma
    severity: high
    tactics:
      - reconnaissance
    techniques:
      - T1590
    data_sources:
      - webserver
  - title: Detect XML-RPC Brute Force Attempt
    description: Detects repeated POST requests to xmlrpc.php, a common target for brute-force attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rules for PROPFIND and XML-RPC monitoring.
      owner: Detection Engineering
      due: 24h
      evidence: Source explicitly identified these as detection-relevant points.
  mitigation_plan:
    - priority: immediate
      action: Patch ownCloud (CVE-2023-49105) and LiteSpeed Cache (CVE-2024-28000).
      owner: IT Operations
      addresses: CVE-2023-49105, CVE-2024-28000
      evidence: Source identifies these as the primary entry vectors.
---

Security researchers have identified a suspected Chinese-speaking threat actor targeting Philippine governmental organizations and naval contractors. The adversary is leveraging known vulnerabilities in public-facing web applications to gain initial access, facilitate data exfiltration, and establish persistence. Specific targets included the Philippine nuclear research body and a defense-affiliated naval contractor. The campaign exhibits sophisticated tradecraft, including the use of randomized sleep intervals to evade volumetric network detection and the deployment of an EtherHiding loader mechanism that retrieves malicious payloads directly from Ethereum smart contracts. The operator successfully exfiltrated a 192 MB SQL dump containing ZKTeco BioTime attendance and personnel data. The targeting suggests a strategic interest in Philippine science, research, and defense sectors.

## Attack Chain

1. Initial access to ownCloud infrastructure obtained by exploiting CVE-2023-49105 (information disclosure vulnerability).
2. Abuse of WebDAV pre-signed URLs to perform reconnaissance via PROPFIND requests with Depth: 1 headers.
3. Exfiltration of files distributed across multiple compromised user accounts to evade detection.
4. Initial access to a naval contractor via exploitation of CVE-2024-28000 in the LiteSpeed Cache WordPress plugin.
5. Brute force attacks against the WordPress /xmlrpc.php endpoint using wordlists like rockyou.txt to gain administrative or elevated access.
6. Deployment of an EtherHiding loader on a compromised WordPress site to pull secondary payloads from an Ethereum smart contract.
7. Successful exfiltration of a ZKTeco BioTime SQL dump containing personnel and attendance records for affiliated research organizations.

## Impact

The breach resulted in the confirmed exfiltration of sensitive personnel records belonging to multiple Philippine science and research organizations. The impact includes the compromise of PII and operational data stored within ZKTeco BioTime systems. Continued exploitation of these vulnerabilities poses a significant risk to regional defense and research entities, with 174 unique IP addresses observed interacting with the malicious loader mechanism alone.

## Recommendation

* Patch CVE-2023-49105 on all ownCloud instances immediately.
* Update LiteSpeed Cache plugins to remediate CVE-2024-28000.
* Audit web server logs for PROPFIND requests with Depth: 1 headers originating from anomalous sources.
* Disable /xmlrpc.php on all WordPress installations if not strictly required for business operations.
* Deploy the Sigma rules below to detect brute-force attempts and suspicious WebDAV enumeration.

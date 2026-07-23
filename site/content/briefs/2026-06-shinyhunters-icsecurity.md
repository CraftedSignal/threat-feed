---
title: ShinyHunters Ransomware Group Claims icsecurity.com Victim, Exfiltrates 2.7M Records
slug: 2026-06-shinyhunters-icsecurity
description: The financially motivated ShinyHunters ransomware group, operating its shinysp1d3r RaaS, has claimed icsecurity.com as a new victim, compromising over 2.7 million records via credential stuffing and exploitation of cloud services like Snowflake, with the intent to extort through data leakage.
date: "2026-06-18T15:45:22Z"
lastmod: "2026-07-23T04:04:59Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ShinyHunters
cpes:
  - cpe:2.3:a:oracle:concurrent_processing:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:unified_communications_manager:*:*:*:*:-:*:*:*
  - cpe:2.3:a:cisco:unified_communications_manager:*:*:*:*:session_management:*:*:*
  - cpe:2.3:a:cisco:unified_communications_manager_im_and_presence_service:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:unity_connection:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=DB5A9BFC-C8FB-5C07-8F9A-B86B35E387EB&utm_source=rss&utm_medium=rss
tags:
  - ransomware
  - data-theft
  - extortion
  - cloud-security
  - threat-actor-group
  - credential-stuffing
vendors:
  - Oracle
  - Cisco
  - Snowflake Inc.
  - Salesforce
  - Google
  - Anodot
products:
  - Oracle E-Business Suite (EBS)
  - Cisco Unified Communications
  - Snowflake
  - Salesforce
  - Google BigQuery
  - Anodot
  - Oracle E-Business Suite (<= 2025-10-01)
  - Oracle Concurrent_Processing
  - Oracle E-Business Suite 12.2.3 through 12.2.14
  - BI Publisher
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1598
    technique_name: Phishing for Information
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1598
    technique_name: Phishing for Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Data from Information Repositories
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
cves:
  - id: CVE-2025-61882
    cvss: 9.8
    epss: 0.99722
  - id: CVE-2026-20045
    cvss: 8.2
    epss: 0.04307
references:
  - https://www.ransomware.live/group/shinyhunters
  - https://www.securityweek.com/estee-lauder-discloses-impact-from-oracle-ebs-zero-day-hack/
  - https://sploitus.com/exploit?id=DB5A9BFC-C8FB-5C07-8F9A-B86B35E387EB&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: icsecurity.com
  - type: domain
    value: shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion
  - type: domain
    value: breachforums.hn
  - type: domain
    value: toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd.onion
  - type: domain
    value: shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd.onion
  - type: email
    value: shinyc0rp@tuta.io
  - type: url
    value: https://t.me/s/SLSH6
  - type: url
    value: https://t.me/s/andrewfedman
  - type: url
    value: https://t.me/s/shinygr0up
  - type: url
    value: https://t.me/s/specialagentadam
  - type: url
    value: https://sploitus.com/exploit?id=DB5A9BFC-C8FB-5C07-8F9A-B86B35E387EB
  - type: url
    value: https://nvd.nist.gov/vuln/detail/CVE-2025-61882
  - type: url
    value: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
ioc_counts:
  domain: 5
  email: 1
  url: 7
rules:
  - title: Detect Suspected Credential Stuffing Attempts to Web Applications
    description: Detects multiple failed login attempts from a single source IP to common web application login paths, indicative of credential stuffing activity used by groups like ShinyHunters. This often precedes successful unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1110
    data_sources:
      - webserver
  - title: Detect DNS Queries for ShinyHunters Infrastructure
    description: Detects DNS queries to known ShinyHunters data leak sites and communication infrastructure, indicating potential command-and-control or data exfiltration activity associated with the group.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1071.001
      - T1567.002
    data_sources:
      - dns_query
      - windows
rules_count: 2
updates:
  - at: "2026-07-21T11:13:31Z"
    level: L2
    summary: added CVE-2025-61882 +1
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/estee-lauder-discloses-impact-from-oracle-ebs-zero-day-hack/
  - at: "2026-07-23T04:04:59Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=DB5A9BFC-C8FB-5C07-8F9A-B86B35E387EB&utm_source=rss&utm_medium=rss
---

The ShinyHunters ransomware group, a financially motivated data-theft and extortion entity active since 2020, has claimed icsecurity.com as a recent victim. This group, known for high-profile breaches including Ticketmaster via Snowflake, launched its Ransomware-as-a-Service (RaaS) offering, "shinysp1d3r," in 2025. For the icsecurity.com incident, ShinyHunters claims to have compromised over 2.7 million records and other internal corporate data, threatening public data leakage by June 22, 2026, if ransom demands are not met. The group leverages techniques such as credential stuffing against cloud platforms like Snowflake, and exploits vulnerabilities including CVE-2025-61882 in Oracle E-Business Suite and CVE-2026-20045 in Cisco Unified Communications to gain initial access and exfiltrate sensitive data for extortion purposes. They primarily target organizations across technology, consumer services, financial services, and education sectors, with a significant focus on US-based entities.

## Attack Chain

1.  **Initial Access via Credential Stuffing**: ShinyHunters obtains valid credentials (often from prior breaches or infostealer data) and attempts to log into target cloud services (e.g., Snowflake, Salesforce, or other SaaS applications) that may lack robust multi-factor authentication, gaining initial unauthorized access.
2.  **Exploitation of Vulnerabilities**: Attackers may exploit known vulnerabilities, such as CVE-2025-61882 in Oracle E-Business Suite or CVE-2026-20045 in Cisco Unified Communications, to achieve privileged access, establish persistence, or further compromise network infrastructure.
3.  **Lateral Movement and Credential Access**: Once inside, the group leverages alternate authentication material (e.g., application access tokens) and unsecured credentials to move laterally within cloud environments or connected systems, expanding their footprint and access to sensitive data sources.
4.  **Data Collection from Repositories**: ShinyHunters identifies and aggregates sensitive data from various information repositories, including cloud databases (e.g., Google BigQuery), cloud storage, and customer relationship management (CRM) systems (e.g., Salesforce), focusing on PII, financial information, and corporate intellectual property.
5.  **Data Exfiltration Over Web Service**: The aggregated data is exfiltrated from the compromised environment, typically disguised as legitimate traffic over web services, to attacker-controlled infrastructure, often hosted on dark web (.onion) domains.
6.  **Extortion and Data Leakage**: Following successful data exfiltration, the group issues a ransom demand, threatening to publicly leak the stolen data on their dark web data leak sites if the victim fails to pay by a specified deadline, as seen with icsecurity.com.

## Impact

The compromise of icsecurity.com resulted in the theft of over 2.7 million records and other internal corporate data from a US-based technology company. ShinyHunters has a history of targeting 128 victims globally, primarily in the US (94 victims), across sectors including technology (22 victims), consumer services, financial services, and education. If the extortion demands are not met, the group typically publishes the stolen data on its dedicated dark web data leak sites, leading to significant reputational damage, regulatory fines, competitive disadvantage, and potential legal action from affected individuals whose PII has been exposed.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious login attempts and C2 communications.
*   Implement multi-factor authentication (MFA) for all user accounts, especially for cloud services like Snowflake and Salesforce, to mitigate credential stuffing attacks.
*   Patch CVE-2025-61882 on all Oracle E-Business Suite (EBS) installations immediately.
*   Patch CVE-2026-20045 on all Cisco Unified Communications systems immediately.
*   Enable comprehensive logging for web servers, DNS queries, and network connections to allow for detection of suspicious activity like credential stuffing and C2 communication.
*   Block the C2 domains and URLs listed in the IOC table at your network perimeter, DNS resolver, and proxy servers.

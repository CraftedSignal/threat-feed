---
title: MAXHUB Pivot Client Application Vulnerability CVE-2026-6411
slug: 2026-05-maxhub-pivot-vuln
description: A vulnerability exists in MAXHUB Pivot client application versions prior to v1.36.2, where a hardcoded AES key allows attackers to decrypt tenant email addresses and associated metadata, and potentially cause a denial-of-service via unauthorized device enrollment through MQTT.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-6411
  - maxhub
  - pivot
  - broken-crypto
  - dos
vendors:
  - MAXHUB
products:
  - MAXHUB Pivot client application
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: Endpoint Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-127-01
  - https://www.cve.org/CVERecord?id=CVE-2026-6411
  - https://www.maxhub.com/en/support/
rules:
  - title: Detect MAXHUB Pivot Client Application Hardcoded AES Key Usage
    description: Detects potential exploitation of the MAXHUB Pivot client application vulnerability (CVE-2026-6411) by monitoring for suspicious decryption activities indicative of the use of the hardcoded AES key.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Unauthorized Device Enrollment via MQTT (Potential DoS)
    description: Detects potential denial-of-service attempts against MAXHUB Pivot client application by monitoring for unusually high device enrollment activity via MQTT.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability, identified as CVE-2026-6411, affects the MAXHUB Pivot client application versions prior to v1.36.2. The vulnerability stems from the presence of a hardcoded AES key within the application. Successful exploitation allows an attacker to obtain encrypted tenant email addresses and related metadata from any tenant. The encrypted data can be decrypted, enabling access to tenant email addresses and associated information in cleartext. Additionally, an attacker may be able to cause a denial-of-service (DoS) condition by enrolling multiple unauthorized devices into a tenant via MQTT, potentially disrupting tenant operations. This issue was reported to MAXHUB by Malik MAKKES and Yassine BENGANA of Abicom Groupe OCI.

## Attack Chain

1. An attacker identifies a MAXHUB Pivot client application running a version prior to v1.36.2.
2. The attacker gains access to the application's installation directory or memory to extract the hardcoded AES key.
3. The attacker intercepts network traffic or accesses local data stores where tenant email addresses and metadata are stored in encrypted form.
4. The attacker uses the extracted AES key to decrypt the intercepted data, revealing tenant email addresses and associated information in cleartext.
5. (Optional) The attacker enrolls multiple unauthorized devices into a tenant via MQTT, leveraging the vulnerability to flood the system with requests.
6. The excessive number of enrolled devices overwhelms the tenant's resources, leading to a denial-of-service condition.
7. Legitimate users are unable to access or use the MAXHUB Pivot client application, disrupting tenant operations.

## Impact

Successful exploitation of CVE-2026-6411 allows an attacker to access sensitive tenant email addresses and associated metadata in cleartext. This information could be used for further malicious activities, such as phishing or identity theft. Furthermore, an attacker may trigger a denial-of-service condition by enrolling multiple unauthorized devices into a tenant via MQTT, which disrupts tenant operations and potentially leads to financial losses due to downtime and recovery efforts. There is no known public exploitation specifically targeting this vulnerability reported to CISA at this time.

## Recommendation

*   Upgrade the MAXHUB Pivot client application to version v1.36.2 or newer to remediate CVE-2026-6411, as recommended by MAXHUB in their advisory.
*   Implement network segmentation to minimize the exposure of MAXHUB Pivot client application instances to potential attackers, as per CISA's recommended practices.
*   Deploy the Sigma rule "Detect MAXHUB Pivot Client Application Hardcoded AES Key Usage" to detect potential exploitation attempts by monitoring for suspicious decryption activities.

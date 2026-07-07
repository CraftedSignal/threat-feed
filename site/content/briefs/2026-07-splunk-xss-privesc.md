---
title: Splunk XSS Privilege Escalation via Custom URLs in Dashboard (CVE-2024-36992)
slug: 2026-07-splunk-xss-privesc
description: A critical cross-site scripting (XSS) vulnerability, identified as CVE-2024-36992, affects Splunk Enterprise and Splunk Cloud Platform, allowing attackers to achieve privilege escalation by exploiting custom URLs within Splunk dashboards via malicious POST requests to the `splunk_internal_metrics/data/ui/views` endpoint, leading to the creation of new user accounts with elevated access permissions on the Splunk server.
date: "2026-07-03T13:41:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:splunk:splunk:*:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:splunk:splunk_cloud_platform:*:*:*:*:*:*:*:*
tags:
  - xss
  - privilege-escalation
  - splunk
  - cve
  - vulnerability
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Cloud
  - Splunk Enterprise Security
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: This is a composed hunting search that looks for POST requests to splunk_internal_metrics/data/ui/views which can be used to elevate privileges on the Splunk server via custom urls.
    confidence_band: high
cves:
  - id: CVE-2024-36992
    cvss: 5.4
    epss: 0.00304
references:
  - https://advisory.splunk.com/
  - https://github.com/splunk/security_content/blob/main/detections/application/splunk_xss_privilege_escalation_via_custom_urls_in_dashboard.yml
rules:
  - title: Detect POST Requests to Splunk UI View Endpoint (CVE-2024-36992)
    description: Detects HTTP POST requests targeting the `splunk_internal_metrics/data/ui/views` endpoint, which is associated with CVE-2024-36992, a cross-site scripting (XSS) vulnerability leading to privilege escalation in Splunk.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
  - title: Detect High-Privilege Splunk User Creation (CVE-2024-36992 Context)
    description: Detects the creation of new user accounts with administrative or high-level privileges within Splunk's audit logs, which is a common post-exploitation artifact of CVE-2024-36992 and other privilege escalation attacks.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
      - T1136.001
    data_sources:
      - application_log
      - splunk
      - audittrail
rules_count: 2
---

A critical cross-site scripting (XSS) vulnerability, identified as CVE-2024-36992, affects Splunk Enterprise and Splunk Cloud Platform. This flaw allows attackers to achieve privilege escalation by exploiting custom URLs within Splunk dashboards. Malicious POST requests targeting the `splunk_internal_metrics/data/ui/views` endpoint can inject and execute arbitrary JavaScript. Upon execution, typically when a privileged user views the compromised dashboard, the XSS payload facilitates the creation of new user accounts with elevated access permissions on the Splunk server. This vulnerability presents a significant risk, enabling unauthorized administrative control and potential data exfiltration or manipulation within the Splunk environment. Defenders should prioritize patching and monitoring for the specific POST requests and subsequent user creation events.

## Attack Chain

1.  **Initial Access / Vulnerability Exploitation (T1189):** An attacker, potentially with low-privileged access, injects malicious JavaScript into a custom URL field within a Splunk dashboard, exploiting the CVE-2024-36992 XSS vulnerability.
2.  **Payload Delivery (T1059.004):** The crafted XSS payload is delivered via a POST request to the internal Splunk endpoint `/splunk_internal_metrics/data/ui/views`, embedding the malicious script within the dashboard configuration.
3.  **Triggering (T1203):** A privileged Splunk user (e.g., an administrator) accesses or views the compromised dashboard containing the malicious custom URL.
4.  **Client-Side Execution (T1059.004):** The embedded JavaScript executes in the context of the privileged user's browser, leveraging their authenticated session within the Splunk interface.
5.  **Privilege Escalation Action (T1068 / T1098):** The executed script issues commands to the Splunk API, such as `audittrail` actions, to create a new user account with administrative or other high-level privileges.
6.  **Persistence / Unauthorized Account Creation (T1136.001):** A new user account with elevated permissions is successfully created on the Splunk server, granting the attacker persistent access and control.
7.  **Post-Exploitation (TA0011):** The attacker utilizes the newly created privileged account to perform further malicious activities, including data exfiltration, system configuration changes, or deployment of additional implants.

## Impact

The successful exploitation of CVE-2024-36992 leads directly to privilege escalation within the Splunk environment. This enables unauthorized attackers to create new user accounts with administrative or other high-level privileges, effectively gaining full control over the Splunk instance. Such compromise can result in sensitive data exfiltration, manipulation of critical log data, disruption of Splunk services, or the use of the Splunk server as a pivot point for further attacks against integrated systems. While the number of victims is not specified, all organizations utilizing affected versions of Splunk Enterprise and Splunk Cloud Platform are at risk of severe data integrity and confidentiality breaches.

## Recommendation

*   Patch CVE-2024-36992 immediately by applying the latest security updates provided by Splunk, available through the official advisory at `https://advisory.splunk.com/`.
*   Deploy the provided Sigma rule "Detect POST Requests to Splunk UI View Endpoint (CVE-2024-36992)" to identify suspicious activity targeting the `splunk_internal_metrics/data/ui/views` endpoint.
*   Deploy the provided Sigma rule "Detect High-Privilege Splunk User Creation (CVE-2024-36992 Context)" to monitor for unauthorized administrative user account creation.
*   Ensure full logging is enabled for Splunk's internal indexes, specifically `_audit` and `_internal`, as these are critical log sources for detecting this threat.

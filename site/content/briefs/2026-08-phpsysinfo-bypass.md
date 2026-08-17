---
title: phpSysInfo IP Allowlist Bypass
slug: 2026-08-phpsysinfo-bypass
description: A vulnerability in phpSysInfo 3.4.5 and earlier allows unauthenticated attackers to bypass IP-based access controls by spoofing HTTP headers, potentially exposing sensitive system information via xml.php.
date: "2026-08-17T14:54:01Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-application
  - vulnerability
  - cve-2026-55584
vendors:
  - phpSysInfo
products:
  - phpSysInfo (<= 3.4.5)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can spoof these headers to bypass security restrictions and access sensitive system information exposed via xml.php.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52648
  - https://github.com/phpsysinfo/phpsysinfo/security/advisories/GHSA-786w-p5pm-cvgh
  - https://www.cve.org/CVERecord?id=CVE-2026-55584
rules:
  - title: Detect CVE-2026-55584 Exploitation - phpSysInfo IP Bypass
    description: Detects exploitation attempts against CVE-2026-55584 where an attacker requests xml.php while providing header-based IP spoofing.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all phpSysInfo instances to version 3.4.6.
      owner: IT Operations
      due: 48h
      evidence: Vendor fix in version 3.4.6.
    - action: Deploy Sigma detection rule to monitor for suspicious header usage on xml.php.
      owner: Detection Engineering
      due: 24h
      evidence: Exploit-DB PoC demonstrates header injection.
  hunt_leads:
    - lead: Search logs for 403 or 401 statuses for xml.php followed by successful 200 responses from the same source IP containing header-based IP identification.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: PoC shows 200 response when headers are injected.
  mitigation_plan:
    - priority: immediate
      action: Configure web server to strip X-Forwarded-For and Client-IP headers from external traffic.
      owner: IT Operations
      addresses: CVE-2026-55584
      evidence: Vendor fix relies on trusting these headers only from trusted proxies.
---

phpSysInfo versions 3.4.5 and earlier contain a critical configuration vulnerability (CVE-2026-55584) related to how the application determines the client's IP address. The application uses a trust-all approach to HTTP headers such as 'X-Forwarded-For' and 'Client-IP' to verify if a request originates from an authorized address defined in the PSI_ALLOWED configuration. Because there is no mechanism to validate that these headers are coming from a trusted proxy, an unauthenticated remote attacker can inject an authorized IP address into these headers. This manipulation defeats the allowlist protection and provides the attacker with access to the full system information XML exposed through the 'xml.php' endpoint, which contains system configuration, hardware details, and potentially sensitive environment data. This vulnerability was addressed in version 3.4.6.

## Attack Chain

1. Attacker performs reconnaissance to identify a target web server running phpSysInfo 3.4.5.
2. Attacker interacts with 'xml.php' to confirm that IP allowlisting is enforced, receiving a 'Client IP address ... not allowed' message.
3. Attacker identifies the target's IP allowlist configuration by trial or auxiliary discovery if applicable.
4. Attacker crafts an HTTP request to 'xml.php'.
5. Attacker injects the 'X-Forwarded-For' or 'Client-IP' HTTP header containing an IP address authorized in the application's configuration.
6. The web server passes the spoofed header to the vulnerable 'read_config.php' logic.
7. The application incorrectly validates the spoofed header as the source IP and grants access.
8. The application serves the sensitive system information XML to the unauthorized attacker.

## Impact

Successful exploitation allows an unauthenticated attacker to gain unauthorized access to system-level diagnostic and configuration information that is intended to be restricted to specific administrative IP addresses. This information disclosure can facilitate further attacks by revealing underlying system architecture, kernel versions, hardware components, and potentially sensitive environment paths or configuration details.

## Recommendation

- Upgrade all instances of phpSysInfo to version 3.4.6 or later immediately to implement trusted proxy validation.
- Apply the Sigma rule provided below to monitor for incoming HTTP requests that use non-standard IP-identifying headers in a way that suggests exploitation attempts.
- Configure the web server (e.g., Apache/Nginx) to ignore or scrub 'X-Forwarded-For' and 'Client-IP' headers from external requests unless they originate from a known, trusted internal proxy.
- Review access logs for 'xml.php' requests originating from unexpected IP addresses that also contain 'X-Forwarded-For' headers, which may indicate exploitation attempts against this CVE.

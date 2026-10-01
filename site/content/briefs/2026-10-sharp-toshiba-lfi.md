---
title: Unauthenticated Local File Inclusion in Sharp and Toshiba Multifunction Printers
slug: 2026-10-sharp-toshiba-lfi
description: Sharp and Toshiba multifunction printers are vulnerable to an unauthenticated path traversal attack allowing remote actors to read arbitrary sensitive system files via the installed_emanual_down.html endpoint.
date: "2026-10-01T16:12:08Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - Sharp
  - Toshiba
products:
  - Multifunction printers
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Sharp (and Toshiba Tec rebranded) multifunction printers contain an unauthenticated local file inclusion vulnerability that allows remote attackers to read arbitrary files.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Attackers can supply directory traversal sequences such as path=/manual/../../../<path> to access files outside the intended manual directory.
    confidence_band: high
cves:
  - id: CVE-2024-58388
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58388
rules:
  - title: Detect CVE-2024-58388 Exploitation - Path Traversal in installed_emanual_down.html
    description: Detects exploitation attempts against Sharp/Toshiba printers by monitoring for directory traversal sequences in the 'path' parameter of the installed_emanual_down.html endpoint.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to printer management interfaces.
      owner: IT Operations
      due: 24h
      evidence: The vulnerability allows for unauthorized file access without requiring authentication.
    - action: Deploy Sigma detection rule to web server or firewall logs.
      owner: Detection Engineering
      due: 48h
      evidence: Exploitation evidence was first observed by the Shadowserver Foundation on 2024-07-30.
  mitigation_plan:
    - priority: immediate
      action: Isolate affected printers from public internet reach.
      owner: IT Operations
      addresses: CVE-2024-58388
      evidence: Vulnerability allows remote attackers to read arbitrary files.
---

Sharp and Toshiba Tec rebranded multifunction printers contain an unauthenticated local file inclusion (LFI) vulnerability (CVE-2024-58388) residing within the 'installed_emanual_down.html' endpoint. Remote, unauthenticated attackers can leverage this flaw by manipulating the 'path' parameter in HTTP requests. By injecting directory traversal sequences (e.g., ../../../), an attacker can escape the web directory context and access arbitrary files on the underlying filesystem. 

This access poses a significant security risk, as attackers can retrieve sensitive data such as system configuration files, /etc/passwd, and memory coredumps that may contain plaintext credentials. The Shadowserver Foundation reported observing active exploitation of this vulnerability starting on July 30, 2024. Given the nature of multifunction printers often residing on internal management networks, this vulnerability provides an initial foothold or a mechanism to escalate privileges by obtaining credentials for further network movement.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Sharp or Toshiba multifunction printers using device-specific HTTP headers or fingerprinting.
2. Attacker crafts an HTTP GET or POST request targeting the 'installed_emanual_down.html' endpoint on the printer's web interface.
3. Attacker injects a malicious payload into the 'path' parameter, utilizing directory traversal sequences such as 'path=/manual/../../../etc/passwd'.
4. The printer's web server processes the request without sufficient validation of the 'path' parameter.
5. The server returns the contents of the requested file (e.g., '/etc/passwd') in the HTTP response body to the attacker.
6. Attacker exfiltrates additional sensitive files, including system configuration backups or coredump files, to identify user accounts, hashes, or hardcoded administrative credentials.
7. Attacker uses stolen credentials or configuration details to authenticate to the printer's administrative interface or pivot into the internal network.

## Impact

Successful exploitation allows for the unauthorized disclosure of sensitive system information, including credentials and configuration data. This can lead to full device compromise, persistence on the local network, or further lateral movement. Since discovery in July 2024, this vulnerability has been exploited in the wild, representing a critical risk to organizations maintaining these printing devices on exposed network segments.

## Recommendation

* Deploy the provided Sigma rule to web server or firewall logs to detect directory traversal attempts targeting the 'installed_emanual_down.html' endpoint.
* Restrict access to multifunction printer web interfaces to trusted internal management subnets only; disable public internet exposure immediately.
* Apply vendor-supplied firmware updates as soon as they become available for the specific Sharp or Toshiba device models.
* Audit printer logs for anomalous 'GET' requests containing '..' or directory traversal patterns.

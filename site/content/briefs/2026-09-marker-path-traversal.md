---
title: Path Traversal Vulnerability in Marker Upload Handler (CVE-2026-85684)
slug: 2026-09-marker-path-traversal
description: An unauthenticated path traversal vulnerability in the marker library up to version 2.0.0 allows attackers to overwrite or delete arbitrary files on the system by manipulating the file.filename parameter.
date: "2026-09-04T15:26:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vikunja:marker:*:*:*:*:*:*:*:*
vendors:
  - Vikunja
products:
  - marker (<= 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can supply filenames containing directory traversal sequences to write arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2026-85684
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85684
rules:
  - title: Detects CVE-2026-85684 Exploitation - Path Traversal in /marker/upload
    description: Detects exploitation attempts against CVE-2026-85684 where an attacker sends a POST request with directory traversal sequences in the filename parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch affected applications using marker version > 2.0.0
      owner: IT Operations
      due: 24h
      evidence: Source notes marker version 2.0.0 is the vulnerable range
  mitigation_plan:
    - priority: immediate
      action: Block or inspect POST requests to /marker/upload containing directory traversal sequences
      owner: SOC
      addresses: CVE-2026-85684
      evidence: NVD vulnerability description
---

The marker library, through version 2.0.0, contains a critical path traversal vulnerability within its FastAPI-based /marker/upload handler. The vulnerability stems from the application's failure to properly sanitize the file.filename parameter before using it in file system operations. 

This security flaw allows unauthenticated, remote attackers to traverse directories by providing malicious filenames containing sequences like "../" or "..\\". Depending on the application's permissions, an attacker can overwrite critical system files to achieve Remote Code Execution (RCE) or delete existing files to cause a Denial of Service (DoS). This vulnerability is particularly dangerous in high-privilege environments where the web application service account has write access to system-critical directories. Organizations using software that incorporates the marker library are advised to verify their dependencies and ensure they are not exposing the vulnerable upload endpoint to untrusted networks.

## Impact

Successful exploitation of CVE-2026-85684 results in unauthorized file system access. This can lead to full system compromise through the overwriting of binaries, configuration files, or startup scripts, or lead to catastrophic data loss and service interruption via the deletion of necessary application or system components. Given the CVSS 3.1 base score of 9.1, this represents a significant risk to the integrity and availability of any environment running the affected software version.

## Recommendation

* Update any application using the marker library to a version beyond 2.0.0, or apply the specific security patches provided by the package maintainers when available.
* Implement strict input validation on the file.filename parameter to detect and reject directory traversal sequences (e.g., "../", "..\\") before the data is processed by the /marker/upload handler.
* Run the application service with the principle of least privilege, ensuring the service account lacks write access to sensitive system directories.
* Deploy WAF rules to monitor and block POST requests to /marker/upload that contain directory traversal patterns in the filename metadata.

---
title: Path Traversal in Dromara lamp-cloud
slug: 2026-08-lamp-cloud-path-traversal
description: An unauthenticated remote path traversal vulnerability in Dromara lamp-cloud allows attackers to access unauthorized files via the FileAnyoneController component.
date: "2026-08-14T02:05:55Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Dromara
products:
  - lamp-cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19757
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19757
  - https://github.com/dromara/lamp-cloud/issues/412
  - https://vuldb.com/vuln/389602
rules:
  - title: Detects CVE-2026-19757 Exploitation - Path Traversal in FileAnyoneController
    description: Detects exploitation attempts of CVE-2026-19757 by monitoring for path traversal sequences in the bucket or bizType parameters
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review perimeter and application logs for CVE-2026-19757 activity
      owner: SOC
      due: 24h
      evidence: Exploitation has been made public.
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to lamp-cloud File-Upload Controller endpoints
      owner: IT Operations
      addresses: CVE-2026-19757
      evidence: Source describes path traversal via FileAnyoneController.
---

Dromara lamp-cloud, a cloud-based development platform, contains a critical path traversal vulnerability (CVE-2026-19757) affecting all versions up to 5.10.0. The vulnerability is located within the File-Upload Controller component, specifically in FileAnyoneController.java. An unauthenticated remote attacker can exploit this flaw by manipulating the 'bucket' or 'bizType' parameters, which are improperly sanitized before being used in file system operations. This allows the attacker to traverse directories and access files outside the intended scope on the server hosting the application. Public proof-of-concept exploits exist, and the maintainers have not yet provided a resolution. Given the remote, unauthenticated nature of this vulnerability, it poses a significant risk to the confidentiality and integrity of affected deployments.

## Attack Chain

1. Attacker performs reconnaissance to identify endpoints running Dromara lamp-cloud.
2. Attacker probes the file upload functionality hosted by FileAnyoneController.java.
3. Attacker constructs an HTTP request targeting the affected controller endpoint.
4. Attacker injects path traversal sequences (e.g., ../../) into the 'bucket' or 'bizType' query parameters.
5. The application fails to validate or sanitize the path input provided in the parameters.
6. The server-side code resolves the path relative to the application's root directory, escaping the target storage folder.
7. The server returns the contents of sensitive files or enables unauthorized write operations to the file system.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files from the server's file system. Depending on the server's configuration and the privileges of the service account running the lamp-cloud application, this may lead to the exfiltration of configuration files, credentials, or sensitive application data. The scope of impact is potentially high for any organization hosting this software in an internet-facing configuration.

## Recommendation

Prioritize the identification and patching of Dromara lamp-cloud instances in your environment. Until a vendor patch is available, implement the following:

* Monitor web server logs for requests containing path traversal sequences (e.g., "../") targeting the FileAnyoneController.java path.
* Restrict access to the File-Upload Controller endpoints via WAF rules or reverse proxy configurations.
* Audit application service account permissions to ensure the principle of least privilege, minimizing the damage of potential file read attempts.
* Monitor for CVE-2026-19757 exploitation attempts by matching web logs against suspicious character patterns in URI parameters.

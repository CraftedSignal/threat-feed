---
title: CVE-2026-66384 - Improper Path Limitation in JFrog Artifactory
slug: 2026-08-jfrog-artifactory-path-traversal
description: JFrog Artifactory suffers from a path traversal vulnerability that allows an authenticated user to write files to unauthorized locations on the server by manipulating remote-repository configurations.
date: "2026-08-27T21:04:52Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:-:*:*
tags:
  - vulnerability
  - path-traversal
  - cisa-kev
  - jfrog
  - artifactory
vendors:
  - JFrog
products:
  - Artifactory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This can allow an authenticated user to write data outside the intended Docker cache path under specific remote-repository conditions.
    confidence_band: high
cves:
  - id: CVE-2026-66384
    cvss: 5.3
    epss: 0.00264
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-66384
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66384
  - https://docs.jfrog.com/releases/docs/jfrog-security-advisories
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch JFrog Artifactory instances according to vendor release docs
      owner: IT Operations
      due: "2026-09-10"
      evidence: CVE-2026-66384 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Restrict access to remote-repository configuration settings
      owner: Security Operations
      addresses: CVE-2026-66384
      evidence: Vulnerability requires authenticated access to exploit
---

JFrog Artifactory contains a critical path traversal vulnerability (CVE-2026-66384) arising from an improper limitation of pathnames to a restricted directory. This vulnerability allows an authenticated attacker to bypass the intended security controls of the Docker cache path by leveraging specifically configured remote repositories. By manipulating the path parameters during repository interaction, an attacker can write data to arbitrary locations on the host file system. This flaw poses a significant risk to the integrity of the Artifactory host, as it may allow an attacker to overwrite configuration files, binary artifacts, or system files to achieve persistence or escalate privileges. Defenders should identify all instances of JFrog Artifactory, particularly those exposed to untrusted authentication sources, and apply vendor-provided patches or mitigations to prevent unauthorized file system modification.

## Impact

Successful exploitation of this vulnerability permits an authenticated attacker to write files outside of the defined Docker cache directory. This capability can be leveraged to achieve code execution or persistence if an attacker replaces system binaries or configuration files. Organizations running self-managed instances of JFrog Artifactory are at highest risk, as the vulnerability directly impacts the host operating system's integrity. Given the inclusion of this vulnerability in CISA's Known Exploited Vulnerabilities catalog (BOD 26-04), timely remediation is mandated to mitigate the risk of host compromise.

## Recommendation

- Immediately identify and inventory all instances of JFrog Artifactory to assess versioning against the patched releases provided in the JFrog Security Advisories.
- Apply the security patches for CVE-2026-66384 as outlined in the JFrog self-managed release documentation.
- Evaluate internet-facing instances of Artifactory and restrict access to remote repository configuration settings to highly trusted accounts only.
- Implement file integrity monitoring on the host systems running Artifactory to detect unauthorized modifications to configuration files or system directories.
- Comply with CISA BOD 26-04 requirements for vulnerability remediation and forensic triage as specified in the provided directive documentation.

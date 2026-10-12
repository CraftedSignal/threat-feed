---
title: Remote Code Execution in Adminer via SQLite Restriction Bypass
slug: 2026-10-adminer-rce
description: Adminer versions prior to 6.1.1 are vulnerable to remote code execution (RCE) where authenticated SQLite users can bypass security restrictions using UTF-8 byte-order marks to inject and execute PHP code.
date: "2026-10-12T18:37:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adminer:adminer:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - sqlite
vendors:
  - Adminer
products:
  - Adminer (< 6.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can attach a database file at a PHP-served path and create a table named with PHP code to execute it as the web server user.
    confidence_band: high
cves:
  - id: CVE-2026-109347
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109347
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Adminer to 6.1.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109347 remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Adminer instances
      owner: IT Operations
      addresses: CVE-2026-109347
      evidence: Mitigation of authenticated-only attack vector
---

Adminer versions prior to 6.1.1 contain a critical security vulnerability (CVE-2026-109347) allowing authenticated users with access to SQLite functionality to bypass existing restrictions on ATTACH and VACUUM INTO statements. By prefixing these SQL statements with a UTF-8 byte-order mark (BOM), an attacker can circumvent Adminer's security controls. This allows the attacker to attach a database file to a directory accessible by the web server. Subsequently, the attacker can create a table containing arbitrary PHP code. Because the file is placed within a path served by the web server, requesting the file triggers the web server to execute the injected PHP code, leading to remote code execution under the context of the web server service account. This impacts any environment utilizing Adminer for SQLite management where attackers have acquired authenticated access.

## Impact

Successful exploitation of this vulnerability results in full remote code execution on the server hosting the Adminer interface. Attackers can leverage this to gain persistence, escalate privileges within the server environment, or exfiltrate sensitive data from the underlying database and file system. Organizations managing web-accessible database administration tools are particularly at risk, as the web interface provides a direct conduit for code execution.

## Recommendation

1. Upgrade Adminer to version 6.1.1 or later immediately to patch the restriction bypass vulnerability associated with CVE-2026-109347.
2. Restrict access to the Adminer interface via network-level controls such as IP allowlisting, VPN access, or mutual TLS to prevent unauthorized parties from obtaining the authentication required to initiate the attack.
3. Audit web server logs for unusual SQL patterns or requests to non-standard file paths in directories that store database or application files.

---
title: Unauthenticated Insecure Deserialization in b2evolution CMS
slug: 2026-09-b2evolution-deserialization
description: b2evolution CMS versions 6.7.8 through 7.2.5 are vulnerable to insecure deserialization via improper validation of serialized objects containing negative integer array keys.
date: "2026-09-17T17:58:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:b2evolution:b2evolution:6.7.8:*:*:*:*:*:*:*
  - cpe:2.3:a:b2evolution:b2evolution:7.2.5:*:*:*:*:*:*:*
  - cpe:2.3:a:b2evolution:b2evolution:6.7.6:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - deserialization
  - rce
vendors:
  - b2evolution
products:
  - b2evolution CMS (6.7.8-7.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can submit crafted serialized PHP objects via POST requests to htsrv/call_plugin.php that reach unserialize().
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker can instantiate arbitrary PHP objects with attacker-chosen properties that may enable code execution if suitable POP gadget chains exist.
    confidence_band: high
cves:
  - id: CVE-2016-8901
    cvss: 9.8
    epss: 0.02653
  - id: CVE-2026-76834
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76834
rules:
  - title: Detect CVE-2026-76834 Exploitation - Malicious Deserialization Attempt
    description: Detects potential insecure deserialization attempts by identifying serialized PHP arrays with negative keys in POST requests to the call_plugin endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade b2evolution CMS to a non-vulnerable version.
      owner: IT Operations
      due: 48h
      evidence: Source states versions 6.7.8 through 7.2.5 contain the vulnerability.
    - action: Deploy the provided Sigma rule to web server logs.
      owner: Detection Engineering
      due: 24h
      evidence: Rule targets the documented vulnerable endpoint and input vector.
  hunt_leads:
    - lead: Search logs for POST requests to htsrv/call_plugin.php containing serialized objects.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability vector is specifically documented in the source.
  mitigation_plan:
    - priority: immediate
      action: Upgrade b2evolution CMS.
      owner: IT Operations
      addresses: CVE-2026-76834
      evidence: Source identifies fixed versions are required.
---

b2evolution CMS versions 6.7.8 through 7.2.5 contain an incomplete fix for CVE-2016-8901, leaving the application susceptible to insecure deserialization attacks. The vulnerability resides in the param_check_serialized_array() function, which fails to correctly reject serialized PHP payloads containing negative integer array keys. An unauthenticated attacker can exploit this flaw by sending a crafted, malicious serialized PHP object via a POST request to the htsrv/call_plugin.php endpoint. 

If the application reaches the unserialize() function with this crafted payload, it results in the instantiation of arbitrary PHP objects. If a suitable Property-Oriented Programming (POP) gadget chain is present within the application environment or associated plugins, the attacker can leverage this instantiation to achieve remote code execution. This vulnerability represents a significant security risk for organizations running affected versions of b2evolution, as it allows for unauthorized interaction with the application backend without prior authentication.

## Impact

Successful exploitation of CVE-2026-76834 allows unauthenticated attackers to instantiate arbitrary PHP objects, which can lead to remote code execution when combined with appropriate gadget chains. This may result in full system compromise, data exfiltration, or unauthorized modification of the content management system. The vulnerability affects all users of b2evolution CMS versions 6.7.8 through 7.2.5.

## Recommendation

- Upgrade b2evolution CMS to a version beyond 7.2.5 that resolves the incomplete validation logic for CVE-2026-76834.
- Implement web application firewall (WAF) rules to inspect POST requests directed at /htsrv/call_plugin.php for serialized PHP objects (strings starting with 'a:' or 'O:') that contain negative integer array keys.
- Audit existing plugins for the presence of dangerous magic methods (e.g., __destruct, __wakeup) that could serve as POP gadgets for insecure deserialization.

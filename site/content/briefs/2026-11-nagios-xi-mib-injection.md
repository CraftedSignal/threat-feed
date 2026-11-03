---
brief_id: brief-2026-11-03-nagios-xi-mib-injection
event_id: brief-2026-11-03-nagios-xi-mib-injection
revision: 1
activity_at: "2026-11-03T18:02:02Z"
title: 'Nagios XI: OS command injection in MIB upload feature (CVE-2026-119742)'
slug: 2026-11-nagios-xi-mib-injection
description: Nagios XI before 2026R2 contains an OS command injection vulnerability in the MIB upload feature, allowing an authenticated administrator to execute arbitrary commands via crafted filenames containing shell metacharacters.
date: "2026-11-03T18:02:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:nagios:nagios_xi:*:*:*:*:*:*:*:*
tags:
  - webserver
  - command-injection
  - vulnerability
vendors:
  - Nagios
products:
  - Nagios XI (< 2026R2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: An authenticated administrator can upload a MIB file with a crafted filename using tab characters to bypass the deny-list and pipe to sh via a multipart POST request to mibs.php.
    confidence_band: high
cves:
  - id: CVE-2026-119742
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119742
rules:
  - title: Detect CVE-2026-119742 Exploitation - Command Injection via MIB Upload
    description: Detects attempts to exploit CVE-2026-119742 by monitoring for shell metacharacters in POST requests to the mibs.php file.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Nagios XI to version 2026R2 or later
      owner: IT Operations
      due: 48h
      evidence: Nagios XI before 2026R2 contains an OS command injection vulnerability
  hunt_leads:
    - lead: Inspect web server logs for POST requests to mibs.php containing shell metacharacters
      technique_id: T1059.004
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An authenticated administrator can upload a MIB file with a crafted filename using tab characters to bypass the deny-list and pipe to sh.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2026R2
      owner: IT Operations
      addresses: CVE-2026-119742
      evidence: Nagios XI before 2026R2 contains an OS command injection vulnerability
---

Nagios XI versions prior to 2026R2 are susceptible to OS command injection via the MIB upload functionality. The vulnerability exists within the install_mib() function in mibs.php, which fails to adequately sanitize uploaded filenames. Specifically, the character-substitution filter omits semicolons, pipes, and non-space IFS (Internal Field Separator) whitespace characters before passing the filename to a grep command executed via the system exec() function. An authenticated administrator can bypass this filter by utilizing tab characters within a multipart POST request to mibs.php, leading to command execution under the context of the web server user.

## Impact

Successful exploitation allows an authenticated administrator to execute arbitrary OS commands as the web server user, potentially leading to full system compromise of the Nagios XI server.

## Recommendation

- Upgrade Nagios XI to version 2026R2 or later immediately to patch the vulnerable install_mib() function.
- Review administrative account activity for unauthorized access or suspicious changes to MIB configurations.
- Restrict access to the MIB upload feature to only highly trusted administrative users until the patch is applied.

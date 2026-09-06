---
title: MediaWiki Remote Code Execution via PHP Deserialization
slug: 2026-09-mediawiki-rce
description: MediaWiki is vulnerable to remote code execution (CVE-2026-58025) via insecure PHP deserialization within the LogEntryBase::extractParams method, allowing authenticated sysop users to execute arbitrary code through malicious XML imports.
date: "2026-09-06T22:54:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mediawiki:mediawiki:*:*:*:*:*:*:*:*
  - cpe:2.3:a:mediawiki:mediawiki:1.46.0:rc0:*:*:*:*:*:*
tags:
  - remote-code-execution
  - deserialization
  - mediawiki
vendors:
  - Wikimedia
products:
  - MediaWiki (< 1.43.9, < 1.44.6, < 1.45.4, < 1.46.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with 'import' or 'importupload' privileges can craft a malicious XML import file to achieve RCE.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability leads to arbitrary object instantiation and RCE gadget chain execution.
    confidence_band: high
cves:
  - id: CVE-2026-58025
    cvss: 9.8
    epss: 0.00503
  - id: CVE-2026-58037
    cvss: 6.1
    epss: 0.0027
references:
  - https://phabricator.wikimedia.org/T422244
  - https://github.com/wikimedia/mediawiki/commit/60f154d4618063ac4d5832285fc246b8fcd7c72c
rules:
  - title: Detect MediaWiki XML Import Attempt
    description: Detects POST requests to Special:Import, which is the primary vector for CVE-2026-58025
    platform: sigma
    severity: medium
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade MediaWiki to version 1.43.9, 1.44.6, 1.45.4, or 1.46.0
      owner: IT Operations
      due: 24h
      evidence: Source provides confirmed fixed versions
  hunt_leads:
    - lead: Search logs for POST requests to /Special:Import from accounts that do not typically perform administrative tasks
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attack requires sysop-level access to import functionality
  mitigation_plan:
    - priority: immediate
      action: Revoke import/upload permissions from non-essential accounts
      owner: IT Operations
      addresses: CVE-2026-58025
      evidence: Exploit requires import/importupload privileges
---

CVE-2026-58025 is a critical deserialization vulnerability in MediaWiki affecting versions prior to 1.43.9, 1.44.6, 1.45.4, and 1.46.0. The vulnerability resides in the `LogEntryBase::extractParams()` method, which improperly calls PHP's `unserialize()` function on user-controlled `log_params` data without implementing class restrictions. An attacker possessing 'import' or 'importupload' privileges (typically members of the 'sysop' group) can supply a crafted XML file containing serialized PHP objects via the `Special:Import` interface. When MediaWiki processes these log items, it triggers the instantiation of malicious objects, enabling a gadget chain that leads to remote code execution. This issue, tracked under Phabricator T422244, also necessitated a fix for a related information disclosure/injection vulnerability, CVE-2026-58037, regarding raw HTML parameter formatting in log entries. Organizations should immediately update to the patched versions released by the Wikimedia Foundation.

## Attack Chain

1. Attacker authenticates to a MediaWiki instance with an account holding 'import' or 'importupload' privileges.
2. Attacker generates a malicious XML export file containing a crafted `<params>` field within a `<logitem>` element.
3. The `<params>` field contains a serialized PHP object payload designed to trigger a known gadget chain.
4. Attacker uploads the malicious XML file via the `Special:Import` endpoint (POST `/wiki/Special:Import`).
5. MediaWiki `WikiImporter` processes the XML and stores the malicious `log_params` payload into the database via `WikiRevision::importLogItem`.
6. Subsequent access to the log entry (e.g., via `RecentChange::parseParams` or database log reading) triggers `LogEntryBase::extractParams`.
7. The application executes `unserialize()` on the malicious blob without class validation.
8. PHP instantiates the malicious object, executing the gadget chain and achieving remote code execution as the web server user.

## Impact

Successful exploitation allows for full remote code execution on the underlying server, granting attackers the ability to compromise the MediaWiki application, access sensitive database content, or pivot further into the internal network. Given the high privileges required for the attack (sysop access), the vulnerability provides an escalation path for already-authenticated administrative users to take complete control of the web server.

## Recommendation

Prioritize patching MediaWiki instances to versions 1.43.9, 1.44.6, 1.45.4, or 1.46.0 immediately. If patching is not immediately feasible, restrict access to `Special:Import` or revoke 'import' and 'importupload' permissions from non-essential accounts. Enable rigorous monitoring of web server logs for POST requests to `Special:Import` from non-administrative or anomalous user sessions.

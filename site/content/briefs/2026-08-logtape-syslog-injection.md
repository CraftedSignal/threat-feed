---
title: Log Injection Vulnerability in @logtape/syslog
slug: 2026-08-logtape-syslog-injection
description: The @logtape/syslog library is vulnerable to syslog injection via unescaped control characters and unvalidated structured data keys, allowing attackers to forge log records in downstream systems.
date: "2026-08-26T20:21:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - injection
  - cve-2026-54511
products:
  - '@logtape/syslog'
cves:
  - id: CVE-2026-54511
    cvss: 8.6
references:
  - https://github.com/advisories/GHSA-8h6h-x5pq-56fq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54511
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch @logtape/syslog in all affected applications
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-54511 remediation
  mitigation_plan:
    - priority: immediate
      action: 'Review logging configuration for includeStructuredData: true'
      owner: IT Operations
      addresses: CVE-2026-54511
      evidence: 'Source advisory states vulnerability only affects deployments with includeStructuredData: true'
---

The @logtape/syslog library contains two output-encoding vulnerabilities (CVE-2026-54511) affecting deployments where `includeStructuredData` is set to `true`. First, the `escapeStructuredDataValue()` function fails to escape C0 control characters (U+0000 - U+001F), including newlines and carriage returns. In environments using TCP syslog with non-transparent framing (RFC 6587), an attacker-controlled log property containing a newline can terminate the current log frame and inject a new, forged syslog record. 

Second, the library fails to validate SD-NAME keys according to RFC 5424 specifications. If an application forwards attacker-controlled metadata - such as HTTP headers or user-supplied parameters - as structured data keys, an attacker can inject structural characters (like `]`) to break the log format or cause further injection. These vulnerabilities allow attackers to forge logs, manipulate severity/facility levels, and undermine the integrity of downstream SIEM systems like Splunk or Elastic Stack.

## Impact

Successful exploitation allows an attacker to inject arbitrary log entries into downstream infrastructure. This can be used to forge audit logs, obscure malicious activity, or break log ingestion pipelines. Any organization relying on @logtape/syslog to forward application logs to a centralized collector is at risk if they allow user-controlled input to influence log properties.

## Recommendation

* Update @logtape/syslog to the latest patched version immediately (v1.3.11, v2.0.14, or v2.1.5+).
* Review applications using the `includeStructuredData: true` configuration to identify and sanitize any user-controlled input being passed as log properties.
* Audit downstream logging infrastructure (rsyslog, syslog-ng, SIEM collectors) to ensure they are configured to ignore or sanitize records that do not strictly adhere to expected RFC 5424 structured data formats.

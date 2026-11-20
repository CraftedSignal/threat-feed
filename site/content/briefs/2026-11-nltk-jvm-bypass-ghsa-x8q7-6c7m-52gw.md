---
brief_id: brief-2026-11-20-nltk-jvm-bypass-ghsa-x8q7-6c7m-52gw
event_id: brief-2026-11-20-nltk-jvm-bypass-ghsa-x8q7-6c7m-52gw
revision: 1
activity_at: "2026-11-20T02:03:21Z"
title: 'NLTK: JVM Argument Injection and Sandbox Bypass (CVE-2026-128138)'
slug: 2026-11-nltk-jvm-bypass-ghsa-x8q7-6c7m-52gw
description: NLTK 3.10.3 contains an incomplete fix for JVM argument injection, allowing execution of attacker-selected Java bytecode via unvalidated launcher tokens in the cmd or java_class arguments.
date: "2026-11-20T02:03:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:nltk:nltk:3.10.3:*:*:*:*:*:*:*
products:
  - nltk
cves:
  - id: CVE-2026-128138
    cvss: 9.8
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-128138
  - https://github.com/advisories/GHSA-x8q7-6c7m-52gw
---

## Overview
NLTK (Natural Language Toolkit) version 3.10.3 contains an incomplete security fix for JVM argument-injection and untrusted JAR/classpath execution paths in `nltk.internals.java()`. While previous hardening validated Java launcher tokens in the `options` channel, the 3.10.3 implementation fails to require the first token of the caller-controlled `cmd` sequence to be a main class. Consequently, supplying `-jar` or an `@argfile` via `nltk.internals.java` or `StanfordSegmenter.java_class` allows execution of attacker-selected Java bytecode.

## Attack Chain
An attacker able to influence the `cmd` parameter of `nltk.internals.java()` or the `java_class` argument of `StanfordSegmenter` can inject Java launcher tokens. These tokens are appended to the command sequence and passed to `subprocess.Popen` without verification. The Java child process executes with the privileges of the parent Python process. This is not a claim that importing NLTK alone is remotely exploitable; the vulnerability is reachable only when these argument channels are exposed to untrusted input.

## Impact
Successful exploitation allows the execution of attacker-selected Java bytecode with the privileges of the process using NLTK.

## Recommendation
Upgrade to version 3.10.4. In environments where patching is not possible, audit application code to ensure input values provided to `cmd` or `java_class` are restricted from using Java launcher switches or `@argfile` references.

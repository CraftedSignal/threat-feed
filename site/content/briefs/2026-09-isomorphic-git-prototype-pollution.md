---
title: Prototype Pollution in isomorphic-git getRemoteInfo
slug: 2026-09-isomorphic-git-prototype-pollution
description: A prototype pollution vulnerability in isomorphic-git before 1.42.0 allows malicious Git server operators to manipulate proxy configurations and intercept credentials via crafted ref advertisements.
date: "2026-09-10T23:10:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:isomorphic-git:isomorphic-git:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - prototype-pollution
  - supply-chain
products:
  - isomorphic-git (< 1.42.0)
cves:
  - id: CVE-2026-89011
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89011
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Update isomorphic-git to 1.42.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source states 1.42.0 is the fixed version
  mitigation_plan:
    - priority: immediate
      action: Upgrade isomorphic-git to 1.42.0 or later
      owner: IT Operations
      addresses: CVE-2026-89011
      evidence: NVD vulnerability disclosure
---

isomorphic-git versions prior to 1.42.0 are vulnerable to a prototype pollution attack within the getRemoteInfo function. The vulnerability arises when the library parses Git ref advertisements during negotiation. By providing a specially crafted reference name containing '__proto__' segments (e.g., '__proto__/corsProxy'), a malicious Git server can inject properties into the global Object.prototype.

This injection allows an attacker to redefine global properties used by the library. Specifically, an attacker can redirect network traffic through an arbitrary, attacker-controlled proxy server. When a client application using a vulnerable version of isomorphic-git interacts with the malicious repository, the library may trigger its onAuth callback, causing the leakage of sensitive authentication credentials to the attacker-supplied proxy. This vulnerability presents a high risk for CI/CD environments and developer tools that automate Git interactions with external, potentially untrusted repositories.

## Impact

Successful exploitation allows for the interception of authentication credentials used by applications relying on isomorphic-git. This affects any ecosystem or service performing automated Git operations on untrusted remotes, potentially leading to unauthorized access to internal development environments, private repositories, or cloud services.

## Recommendation

* Update the isomorphic-git dependency to version 1.42.0 or later across all projects.
* Audit applications for dependencies using isomorphic-git to interact with external or user-provided Git repositories.
* Review CI/CD pipeline configurations to ensure that clones or fetches from untrusted repositories are executed in isolated, ephemeral environments with restricted network access.
* Monitor for abnormal outbound connections originating from build servers or developer machines that execute isomorphic-git operations.

---
brief_id: brief-2026-11-23-gradle-repo-exposure-ghsa-w78c-w6vf-rw82
event_id: brief-2026-11-23-gradle-repo-exposure-ghsa-w78c-w6vf-rw82
revision: 1
activity_at: "2026-11-23T16:50:14Z"
title: 'Gradle: Repository resolution dependency hijacking (CVE-2026-22816)'
slug: 2026-11-gradle-repo-exposure-ghsa-w78c-w6vf-rw82
description: Gradle versions before 8.14.4 and 9.3.0 fail to properly disable repositories when encountering an UnknownHostException, potentially allowing attackers to serve malicious artifacts via registered but previously unresolvable domain names.
date: "2026-11-23T16:50:14Z"
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
  validation_status: test_defined
cpes:
  - cpe:2.3:a:gradle:gradle:*:*:*:*:*:*:*:*
vendors:
  - Gradle
products:
  - gradle-core
product_versions:
  - product: gradle-core
    range: < 8.14.4
  - product: gradle-core
    range: '>= 9.0.0, < 9.3.0'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    subtechnique_name: Compromise Software Dependencies
    evidence: This behavior could allow an attacker to register a service under the host name used by the build and serve malicious artifacts.
    confidence_band: high
cves:
  - id: CVE-2026-22816
    cvss: 7.4
    epss: 0.00174
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-w78c-w6vf-rw82
  - https://cveawg.mitre.org/api/cve/CVE-2026-22816
action_plan:
  priority: elevated
  immediate_actions:
    - action: Upgrade Gradle to version 8.14.4 or 9.3.0 on all CI/CD build environments.
      evidence: Gradle has introduced a change in behavior in Gradle 9.3.0 and 8.14.4 to stop searching other repositories when encountering these errors.
  hunt_leads:
    - lead: Review Gradle build scripts and configuration files (build.gradle, settings.gradle) for repositories using hardcoded hostnames that might be prone to domain expiration or typos.
      data_needed:
        - Build configuration files
        - DNS resolution logs for build servers
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An unresolvable host name could be caused by allowing a repository's domain name registration to lapse or typo-ing the real domain name.
  mitigation_plan:
    - priority: immediate
      action: Configure and enforce repository content filtering and dependency verification in all projects.
      evidence: If you cannot update to a newer Gradle version, configuring dependency verification is the best way to make sure your build resolves the dependencies you expect and nothing else.
---

## Overview
Gradle versions prior to 8.14.4 and 9.3.0 contain a vulnerability where certain connection exceptions, specifically UnknownHostException, are not treated as fatal errors during dependency resolution. If a configured repository host becomes unresolvable, Gradle may continue searching subsequent repositories listed in the build configuration instead of halting. An attacker can exploit this by registering an unresolvable domain name used in a build configuration or by waiting for an existing repository's domain registration to expire, subsequently serving malicious artifacts to builds that fall back to the attacker-controlled host.

## Attack Chain
1. Attacker identifies a build configuration that lists an unresolvable repository host (due to domain expiration, typo, or DNS misconfiguration) before other legitimate repositories.
2. Gradle initiates dependency resolution and attempts to contact the unresolvable host.
3. The host triggers an UnknownHostException.
4. Gradle, failing to treat the error as fatal, proceeds to the next repository in the declared list.
5. The attacker, having registered the unresolvable domain, responds to the Gradle request.
6. Gradle resolves and pulls malicious artifacts from the attacker-controlled repository.

## Impact
Successful exploitation allows an attacker to inject malicious artifacts into the build process, potentially leading to supply chain compromise. The impact includes the execution of arbitrary code during build time if the injected artifacts are malicious.

## Recommendation
- Upgrade to Gradle 8.14.4 or 9.3.0 immediately.
- If patching is not feasible, enable dependency verification in your Gradle builds to ensure only trusted, cryptographically verified artifacts are used.
- Enforce strict repository content filtering to restrict which dependencies can be resolved from specific repositories.
- Audit build configurations for unused, outdated, or typo-ridden repository declarations.

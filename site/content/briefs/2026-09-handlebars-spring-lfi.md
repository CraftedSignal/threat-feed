---
title: Arbitrary File Read in Handlebars.java SpringTemplateLoader via URL Fragment Bypass
slug: 2026-09-handlebars-spring-lfi
description: An unauthenticated arbitrary file read vulnerability (CVE-2026-63490) exists in handlebars-springmvc < 4.5.3 due to insufficient validation of user-influenced view names, allowing attackers to bypass file suffix restrictions using URL fragments.
date: "2026-09-03T00:03:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:handlebars_project:handlebars.java:*:*:*:*:*:*:*:*
tags:
  - cve-2026-63490
  - arbitrary-file-read
  - spring-mvc
  - template-injection
vendors:
  - Handlebars.java
products:
  - handlebars-springmvc (< 4.5.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Unauthenticated, network-reachable, arbitrary file read of any file reachable by the JVM process.
    confidence_band: high
cves:
  - id: CVE-2026-63490
    cvss: 7.5
    epss: 0.0047
references:
  - https://github.com/advisories/GHSA-g29j-rwfv-h99w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63490
rules:
  - title: Detects CVE-2026-63490 Exploitation - Suspicious View Resolution via Web Request
    description: Detects potential attempts to exploit CVE-2026-63490 by identifying HTTP requests containing URL fragments in parameters associated with view name resolution
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade handlebars-springmvc to 4.5.3 or later
      owner: IT Operations
      due: 24h
      evidence: Source specifies 4.5.3 as the patched version for CVE-2026-63490
  enrichment_needed:
    - item: Identify all Java services using handlebars-springmvc
      owner: Security Engineering
      reason: Asset inventory required to prioritize patching
      evidence: Product affects versions < 4.5.3
  hunt_leads:
    - lead: Search logs for unusual view resolution attempts containing file protocols or fragments
      technique_id: T1566
      data_needed:
        - Web application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary file read via fragments
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to reject requests containing '#' in view-related parameters
      owner: Security Engineering
      addresses: CVE-2026-63490
      evidence: Fix suggested by remediation section
---

Handlebars.java version 4.5.3 and earlier is vulnerable to an arbitrary file read vulnerability (CVE-2026-63490) within the `SpringTemplateLoader` component. The vulnerability arises because `SpringTemplateLoader` trusts Spring's `ResourceLoader` to resolve view names without applying the path-containment checks implemented in other loaders. The security boundary protecting the system relies on an unconditional `.hbs` suffix appended by `AbstractTemplateLoader`.

Attackers can bypass this suffix check by appending a URL fragment (`#`) to a user-influenced view name. Spring and the JDK treat the content following the fragment as metadata and discard it during resource resolution, effectively stripping the `.hbs` extension. This allows an attacker to manipulate the view path to point to arbitrary files on the filesystem readable by the JVM process. Successful exploitation leads to unauthenticated access to sensitive system files, including configuration files, API keys, CI/CD secrets, and service account tokens. This is particularly critical in Spring MVC applications that resolve view names based on user input.

## Attack Chain

1. Attacker identifies a Spring MVC controller endpoint that returns a view name derived from user input (e.g., via query parameter or path variable).
2. Attacker crafts a malicious view name request containing a protocol prefix (e.g., `file:`) and the target file path.
3. Attacker appends a `#` character to the end of the path (e.g., `file:/etc/passwd#`).
4. `HandlebarsViewResolver` passes the attacker-influenced string to the `handlebars.compile()` method.
5. `SpringTemplateLoader` processes the path, and `AbstractTemplateLoader` appends `.hbs` after the `#` fragment.
6. Spring's `ResourceLoader` resolves the path, discarding the fragment part (`#.hbs`).
7. The application parses and renders the contents of the target file as a Handlebars template.
8. The HTTP response body returns the contents of the sensitive file to the attacker.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive files accessible to the application process UID. This includes, but is not limited to, `application.yml` files containing database credentials and secret keys, cloud environment credentials (AWS/GCP), Kubernetes service account tokens, private keys, and environment variables. These primitives enable full-system compromise, lateral movement within a network, or escalation of privileges in cloud-native environments.

## Recommendation

Prioritize patching to version 4.5.3 or later of `handlebars-springmvc`. For applications where immediate patching is not possible, implement input validation in the view resolver to reject view names containing prohibited characters.

* Upgrade the `com.github.jknack:handlebars-springmvc` dependency to version 4.5.3 or higher to incorporate the fix for CVE-2026-63490.
* Implement an input validation layer in `HandlebarsViewResolver.configure` to detect and reject view names containing `:` or `#` characters.
* Conduct a code audit of all Spring MVC controllers to identify and refactor patterns where user input influences view names or template paths.
* Restrict file access for the JVM process to only necessary directories to minimize the impact of potential arbitrary file read primitives.

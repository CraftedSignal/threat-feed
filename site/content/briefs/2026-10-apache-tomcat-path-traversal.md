---
brief_id: brief-2026-10-29-apache-tomcat-path-traversal
event_id: brief-2026-10-29-apache-tomcat-path-traversal
revision: 2
activity_at: "2026-11-01T05:57:03Z"
revision_history:
  - revision: 2
    at: "2026-11-01T05:57:03Z"
    checksum: sha256:a0ac74fc5b0407daab52b1c939f8892730080f0ab6604c0d99d115a5d38e964e
    summary: added coverage for Tomcat (7.0.0-7.0.109) +4 products
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-COVEPSENG-CVE-2026-43512-POC&utm_source=rss&utm_medium=rss
title: 'Apache Tomcat: Path traversal via RewriteValve (CVE-2025-55752)'
slug: 2026-10-apache-tomcat-path-traversal
description: A path traversal vulnerability (CVE-2025-55752) in the Apache Tomcat RewriteValve component allows unauthenticated attackers to bypass security constraints and access protected files like /WEB-INF/web.xml by abusing an improper URL normalization-before-decoding processing order.
date: "2026-10-29T22:23:16Z"
lastmod: "2026-11-01T05:56:11Z"
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
  - cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*
tags:
  - apache-tomcat
  - path-traversal
  - cve-2025-55752
  - webserver
  - authentication-bypass
vendors:
  - Apache
products:
  - Tomcat (11.0.0-M1 to 11.0.10)
  - Tomcat (10.1.0-M1 to 10.1.44)
  - Tomcat (9.0.0-M11 to 9.0.108)
  - Tomcat (8.5.6 to 8.5.100)
  - Tomcat (7.0.0-7.0.109)
  - Tomcat (8.5.0-8.5.100)
  - Tomcat (9.0.0.M1-9.0.117)
  - Tomcat (10.1.0.M1-10.1.54)
  - Tomcat (11.0.0.M1-11.0.21)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Path traversal in Apache Tomcat RewriteValve via URL-encoded sequences bypassing /WEB-INF/.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.002
    subtechnique_name: Pass the Hash
    evidence: A client that submits a DIGEST response computed with the literal string 'null' as the password produces an identical hash.
    confidence_band: high
cves:
  - id: CVE-2025-55752
    cvss: 7.5
    epss: 0.64413
    kev_status: "false"
  - id: CVE-2026-43512
    cvss: 9.8
    epss: 0.01326
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-55752
  - https://github.com/apache/tomcat/commit/130d36d8
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MASAHIRO331-CVE-2025-55752&utm_source=rss&utm_medium=rss
  - https://tomcat.apache.org/security-9.html
  - https://github.com/apache/tomcat/commit/6565a6cb6499e56fe2f34457cec99f9d1c4f39e9
  - https://return-zero.dev/posts/cve-2026-43512
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-COVEPSENG-CVE-2026-43512-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-55752 Exploitation Attempt - Path Traversal in RewriteValve
    description: Detects HTTP requests containing URL-encoded path traversal sequences directed at sensitive application directories
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Apache Tomcat to versions 11.0.11+, 10.1.45+, or 9.0.109+
      owner: IT Operations
      due: 48h
      evidence: Source lists these as patched versions for the respective series.
    - action: Deploy WAF signatures to block URI patterns containing URL-encoded traversal sequences
      owner: SOC
      due: 24h
      evidence: Source recommends WAF rules to block ../ and its encoded variants.
    - action: Update Tomcat to 7.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly lists affected versions requiring patching.
  hunt_leads:
    - lead: Search web server logs for suspicious /WEB-INF/ or /META-INF/ access requests containing encoded sequences
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit leverages..%2f to bypass directory restrictions.
    - lead: Search logs for unusual frequency of HTTP 401 Unauthorized errors in Tomcat logs originating from the same source IP, which may indicate automated credential stuffing or bypass attempts.
      technique_id: T1550.002
      data_needed:
        - Tomcat access logs
        - Tomcat security/authentication debug logs (FINE level)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The PoC performs repetitive authentication attempts against protected paths.
  mitigation_plan:
    - priority: immediate
      action: Disable RewriteValve or the PUT method on internet-facing Tomcat servers if they are not required
      owner: IT Operations
      addresses: CVE-2025-55752
      evidence: Source lists these as primary mitigations.
    - priority: immediate
      action: Upgrade Tomcat to 7.0.0 or later
      owner: IT Operations
      addresses: CVE-2026-43512
      evidence: Source provides explicit fixed version numbers.
updates:
  - at: "2026-11-01T05:56:11Z"
    level: L2
    summary: added coverage for Tomcat (7.0.0-7.0.109) +4 products
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-COVEPSENG-CVE-2026-43512-POC&utm_source=rss&utm_medium=rss
---

CVE-2025-55752 is a high-severity path traversal vulnerability affecting Apache Tomcat's RewriteValve. The flaw stems from an incorrect processing order where URL normalization occurs prior to URL decoding. Attackers can exploit this by crafting requests containing URL-encoded path traversal sequences, such as '..%2f', which bypass filters that would normally block access to restricted directories like '/WEB-INF/'.

## Impact

Successful exploitation allows unauthorized disclosure of sensitive server files, including application configuration files such as 'web.xml'. The CVSS v3.1 score is 7.5, reflecting a significant risk to confidentiality and integrity in affected environments.

## Recommendation

- Upgrade Apache Tomcat to the patched versions: 11.0.11+, 10.1.45+, or 9.0.109+. Note that 8.5.x is EOL and will not receive a patch.
- Disable the 'RewriteValve' if it is not strictly required by the application.
- Disable the PUT method if not needed, as a precautionary measure.
- Deploy WAF rules to inspect HTTP request URIs for path traversal patterns, specifically targeting sequences like '../' and their URL-encoded variants (e.g., '%2e%2e%2f', '..%2f').
- Audit existing logs for attempted access to '/WEB-INF/' or '/META-INF/' patterns using encoded sequences.

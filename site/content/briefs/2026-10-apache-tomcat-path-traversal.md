---
brief_id: brief-2026-10-29-apache-tomcat-path-traversal
event_id: brief-2026-10-29-apache-tomcat-path-traversal
revision: 1
activity_at: "2026-10-29T22:23:16Z"
title: 'Apache Tomcat: Path traversal via RewriteValve (CVE-2025-55752)'
slug: 2026-10-apache-tomcat-path-traversal
description: A path traversal vulnerability (CVE-2025-55752) in the Apache Tomcat RewriteValve component allows unauthenticated attackers to bypass security constraints and access protected files like /WEB-INF/web.xml by abusing an improper URL normalization-before-decoding processing order.
date: "2026-10-29T22:23:16Z"
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
vendors:
  - Apache
products:
  - Tomcat (11.0.0-M1 to 11.0.10)
  - Tomcat (10.1.0-M1 to 10.1.44)
  - Tomcat (9.0.0-M11 to 9.0.108)
  - Tomcat (8.5.6 to 8.5.100)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Path traversal in Apache Tomcat RewriteValve via URL-encoded sequences bypassing /WEB-INF/.
    confidence_band: high
cves:
  - id: CVE-2025-55752
    cvss: 7.5
    epss: 0.64413
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-55752
  - https://github.com/apache/tomcat/commit/130d36d8
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MASAHIRO331-CVE-2025-55752&utm_source=rss&utm_medium=rss
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
  immediate_actions:
    - action: Patch Apache Tomcat to versions 11.0.11+, 10.1.45+, or 9.0.109+
      owner: IT Operations
      due: 48h
      evidence: Source lists these as patched versions for the respective series.
    - action: Deploy WAF signatures to block URI patterns containing URL-encoded traversal sequences
      owner: SOC
      due: 24h
      evidence: Source recommends WAF rules to block ../ and its encoded variants.
  hunt_leads:
    - lead: Search web server logs for suspicious /WEB-INF/ or /META-INF/ access requests containing encoded sequences
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit leverages..%2f to bypass directory restrictions.
  mitigation_plan:
    - priority: immediate
      action: Disable RewriteValve or the PUT method on internet-facing Tomcat servers if they are not required
      owner: IT Operations
      addresses: CVE-2025-55752
      evidence: Source lists these as primary mitigations.
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

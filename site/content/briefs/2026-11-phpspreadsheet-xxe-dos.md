---
brief_id: brief-2026-11-01-phpspreadsheet-xxe-dos
event_id: brief-2026-11-01-phpspreadsheet-xxe-dos
revision: 1
activity_at: "2026-11-01T20:48:33Z"
title: 'PhpSpreadsheet: XmlScanner TOCTOU bypass leading to XXE and DoS (CVE-2026-108357)'
slug: 2026-11-phpspreadsheet-xxe-dos
description: A TOCTOU vulnerability in PhpSpreadsheet allows attackers to bypass XML security filters via double-encoded numeric entities, enabling XXE and Denial of Service attacks.
date: "2026-11-01T20:48:33Z"
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
  validation_status: Source-documented POC provides clear reproduction steps
cpes:
  - cpe:2.3:a:phpoffice:phpspreadsheet:*:*:*:*:*:*:*:*
vendors:
  - PHPOffice
products:
  - PhpSpreadsheet (>= 4.0.0, <= 5.9.0)
  - PhpSpreadsheet (>= 3.3.0, <= 3.10.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any application that accepts user-uploaded SpreadsheetML XML files and processes them with PhpSpreadsheet's Xml reader is vulnerable.
    confidence_band: high
cves:
  - id: CVE-2026-108357
    epss: 0.00463
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-rxj4-h86g-25gc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108357
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify applications in the environment leveraging the PhpSpreadsheet library to process untrusted XML uploads.
      owner: SOC
      due: 48h
      evidence: Vulnerability affects applications accepting user-uploaded SpreadsheetML XML files.
  hunt_leads:
    - lead: Search web server logs for HTTP POST requests to endpoints that handle file uploads, specifically looking for XML or Spreadsheet file extensions alongside requests that contain unusual numeric entity patterns like &#38;#60; or &#38;#x3C;.
      technique_id: T1190
      data_needed:
        - Web server access logs (POST body/request content)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The PoC utilizes double-encoded numeric entities to bypass the XML scanner.
  mitigation_plan:
    - priority: immediate
      action: Upgrade PhpSpreadsheet to 8.0 or later
      owner: IT Operations
      addresses: CVE-2026-108357
      evidence: Vendor advisory suggests upgrade to resolve the TOCTOU vulnerability.
---

PhpSpreadsheet contains a Time-of-Check Time-of-Use (TOCTOU) vulnerability (CVE-2026-108357) in its `XmlScanner::scan()` method. The scanner performs two sequential passes over input data, but the `unentity()` callback - which decodes HTML entities - executes *after* the security pattern check in both passes. By using double-encoded numeric entities (e.g., `&#38;#60;`), an attacker can hide `<!DOCTYPE` declarations from the security filter. The first pass decodes the entity into a single-encoded format, and the second pass completes the decoding, resulting in a malicious `<!DOCTYPE` payload that the XML parser then executes.

## Attack Chain

1. Attacker crafts a malicious SpreadsheetML XML file containing double-encoded entities (e.g., `&#38;#60;` for `<`).
2. The `Reader\Xml` component passes the raw file content to `XmlScanner::scan()`.
3. `XmlScanner::scan()` performs a pattern match on the raw input; the malicious `<!DOCTYPE` remains hidden.
4. The `unentity()` callback executes `html_entity_decode()`, converting the double-encoded entity to a single-encoded entity.
5. The partially decoded XML is stored in `Xml::$fileContents`.
6. The `Xml` reader initiates a second scan pass, which also fails to match the pattern because the entity is only partially decoded.
7. The `unentity()` callback executes again, converting the single-encoded entity into the raw `<` character.
8. `simplexml_load_string()` processes the final, now-malicious XML, triggering entity expansion (DoS) or XXE.

## Impact

- **Denial of Service:** Exploitation causes quadratic memory blowup via entity expansion.
- **Information Disclosure:** XXE/SSRF allows unauthorized reading of local files or internal network resources, specifically on PHP versions < 8.0 or when `LIBXML_NOENT` is enabled.

## Recommendation

- Upgrade PhpSpreadsheet to a patched version once available from PHPOffice.
- Audit applications that use `PhpOffice\PhpSpreadsheet\Reader\Xml` to identify intake points for user-supplied SpreadsheetML files.
- Implement file-type validation and strictly forbid `LIBXML_NOENT` if using older PHP environments.

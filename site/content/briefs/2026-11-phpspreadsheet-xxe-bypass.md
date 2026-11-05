---
brief_id: brief-2026-11-05-phpspreadsheet-xxe-bypass
event_id: brief-2026-11-05-phpspreadsheet-xxe-bypass
revision: 1
activity_at: "2026-11-05T13:44:30Z"
title: 'PHPOffice PhpSpreadsheet: XmlScanner bypass allows XXE and DoS (CVE-2026-108358)'
slug: 2026-11-phpspreadsheet-xxe-bypass
description: An XML parsing bypass in PhpSpreadsheet allows attackers to use ISO-2022 escape sequences to evade security filters, leading to potential DoS via entity expansion or XXE/SSRF depending on configuration.
date: "2026-11-05T13:44:30Z"
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
  - cpe:2.3:a:phpoffice:phpspreadsheet:*:*:*:*:*:*:*:*
tags:
  - xxe
  - dos
  - php
  - xml
  - cve-2026-108358
vendors:
  - PHPOffice
products:
  - PhpSpreadsheet (<= 1.30.6)
  - PhpSpreadsheet (2.0.0-2.1.18)
  - PhpSpreadsheet (2.2.0-2.4.7)
  - PhpSpreadsheet (3.3.0-3.10.7)
  - PhpSpreadsheet (4.0.0-5.9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any application using PhpSpreadsheet to process user-uploaded XLSX files is affected.
    confidence_band: high
cves:
  - id: CVE-2026-108358
    epss: 0.00625
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-3x94-m842-937c
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade PhpSpreadsheet to 1.30.7 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly names the vulnerability as bypass of security scanner
  hunt_leads:
    - lead: Search application logs for unusual memory usage spikes or timeouts associated with file upload endpoints.
      technique_id: T1190
      data_needed:
        - Web server error logs
        - Application telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A 2 KB XLSX causes 45 MB peak memory usage (22,000:1 amplification ratio).
  mitigation_plan:
    - priority: immediate
      action: Upgrade PhpSpreadsheet to 1.30.7 or later
      owner: IT Operations
      addresses: CVE-2026-108358
      evidence: Source identifies vulnerable ranges up to 5.9.0
---

The `XmlScanner::scan()` method in PhpSpreadsheet utilizes an insufficient regular expression that only handles NULL byte (0x00) interleaving to detect `<!DOCTYPE` declarations. An attacker can bypass this filter by inserting ISO-2022 escape sequences (0x1B bytes) between the characters of the `DOCTYPE` tag. Because the XML parser performs charset normalization and strips these bytes before processing, the resulting XML becomes a valid document with an injected `DOCTYPE` that was never validated. This allows for Denial of Service through quadratic entity expansion on all PHP versions, and XXE or SSRF on systems running PHP < 8.0 or those configured with `LIBXML_NOENT`.

## Attack Chain

1. Attacker crafts a malicious XLSX archive file containing a specially encoded XML part (e.g., `sharedStrings.xml`).
2. Attacker embeds `<!DOCTYPE` tags within the XML using ISO-2022 escape sequences (e.g., `ESC ( B`) to obfuscate characters.
3. Attacker uploads the file to the target application using PhpSpreadsheet.
4. The application triggers `PhpSpreadsheet\Reader\Security\XmlScanner::scan()` on the uploaded file.
5. The `XmlScanner` regex fails to identify the obfuscated `DOCTYPE` due to the presence of escape sequences.
6. The `SimpleXML` loader processes the XML and performs charset normalization, stripping the escape sequences and revealing the `DOCTYPE`.
7. The XML parser processes the `DOCTYPE`, leading to entity expansion (DoS) or file/network access (XXE/SSRF).

## Impact

Successful exploitation can cause significant resource exhaustion (DoS) via memory-intensive entity expansion. In environments with older PHP versions or specific XML configuration, it facilitates information disclosure and server-side request forgery. A 2 KB malicious XLSX file can result in ~45 MB of peak memory usage.

## Recommendation

1. Update PhpSpreadsheet to the latest patched version immediately.
2. Implement strict file validation for user-uploaded XLSX files to ensure they conform to expected schemas before processing.
3. Limit memory_limit for scripts that process user-supplied spreadsheet files to mitigate the impact of quadratic entity expansion.
4. Ensure `libxml_disable_entity_loader(true)` is explicitly set if using older PHP environments where this is not default.

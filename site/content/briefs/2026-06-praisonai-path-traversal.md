---
title: PraisonAI GitHub template cache path traversal allows outside-cache file write and directory deletion
slug: 2026-06-praisonai-path-traversal
description: PraisonAI's template loader is vulnerable to a path traversal flaw (GHSA-f44v-7qgw-9gh9) when processing GitHub template URIs, allowing an unauthenticated attacker to write arbitrary files or delete arbitrary directories on the system running PraisonAI, leading to corruption of user configuration, project state, or application data.
date: "2026-06-18T15:28:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - application-vulnerability
  - python
  - file-write
  - file-deletion
vendors:
  - PraisonAI
products:
  - praisonai (>= 2.6.0, <= 4.6.57)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1070
    technique_name: ""
references:
  - https://github.com/advisories/GHSA-f44v-7qgw-9gh9
rules:
  - title: Detects GHSA-f44v-7qgw-9gh9 Exploitation - PraisonAI Writing Cache Metadata Outside Expected Path
    description: Detects creation of '.cache_meta.json' files by a PraisonAI or Python process outside the application's designated cache directory, indicating potential GHSA-f44v-7qgw-9gh9 path traversal exploitation for arbitrary file write.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1070.004
      - T1485
    data_sources:
      - file_event
      - windows
  - title: Detects GHSA-f44v-7qgw-9gh9 Exploitation - PraisonAI Deleting Directories Outside Expected Path
    description: Detects a PraisonAI or Python process performing directory deletion activities (shutil.rmtree) on paths outside its legitimate cache, indicative of GHSA-f44v-7qgw-9gh9 path traversal exploitation for arbitrary directory deletion.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1070.004
      - T1485
    data_sources:
      - file_delete
      - windows
rules_count: 2
---

PraisonAI's template loader, particularly versions 2.6.0 through 4.6.57, contains a path traversal vulnerability (GHSA-f44v-7qgw-9gh9) that allows an attacker to manipulate file system operations. The issue stems from insufficient validation of user-controlled `ref` and `template path` segments within GitHub template URIs (e.g., `github:owner/repo/template@v1.0.0`). When a crafted URI with directory traversal sequences (`..`) is processed, PraisonAI's cache layer constructs file paths that escape its intended cache directory. This enables an attacker to either write arbitrary `.cache_meta.json` files to unintended locations or, under specific conditions, delete arbitrary directories on the host system. This vulnerability, distinct from Zip Slip attacks, does not require malicious archives and affects PraisonAI installations across various operating systems, posing a significant risk of data corruption or denial of service.

## Attack Chain

1. An attacker crafts a malicious PraisonAI GitHub template URI containing directory traversal sequences (e.g., `github:attacker/repo/template@../../../../outside-target`) within the `ref` portion.
2. A user or automated service loads this crafted URI using PraisonAI's `TemplateLoader.load()` method.
3. PraisonAI's template resolver (`praisonai/templates/resolver.py`) captures the owner, repo, template path, and the malicious `ref` verbatim without segment validation.
4. The `_get_cache_path()` function in `praisonai/templates/cache.py` concatenates these unvalidated segments to construct a local cache path, resulting in a path that escapes the intended `~/.praison/cache/templates/` directory.
5. **Scenario A (Arbitrary File Write):** During the first load, the `cache.put()` method attempts to write the `.cache_meta.json` file to the attacker-controlled escaped path.
6. **Scenario B (Arbitrary Directory Deletion):** If a legitimate cache entry for the *same owner/repo/template prefix* already exists, a subsequent load with the malicious URI causes `cache.put()` to first call `shutil.rmtree()` on the attacker-controlled escaped path, deleting an arbitrary directory.
7. The attacker successfully performs either the creation of `.cache_meta.json` at an arbitrary location (e.g., corrupting application configuration) or the deletion of an arbitrary directory on the system where PraisonAI is running.
8. This leads to corruption of user configuration, project state, or application data, potentially resulting in denial of service or further compromise.

## Impact

Successful exploitation of this path traversal vulnerability can lead to severe consequences for organizations utilizing PraisonAI. An attacker can create arbitrary files, specifically `.cache_meta.json`, in locations outside the application's intended cache, potentially overwriting critical configuration files or injecting malicious data. More critically, under a specific two-stage scenario, an attacker can trigger the deletion of arbitrary directories via `shutil.rmtree()`, leading to data destruction, corruption of user or project data, or even a complete denial of service by removing essential system directories. All PraisonAI versions from 2.6.0 up to 4.6.57 are affected.

## Recommendation

*   Patch PraisonAI immediately when a fix is released for versions >= 2.6.0 and <= 4.6.57 as per GHSA-f44v-7qgw-9gh9.
*   Deploy the provided Sigma rules to detect suspicious file write and deletion activities initiated by PraisonAI processes.
*   Enable detailed file creation and deletion logging (e.g., Sysmon Event ID 11 for file creation, Event ID 23 for file deletion on Windows; auditd on Linux) for Python processes to activate the detection rules.
*   If PraisonAI is used in a critical environment, implement strict path validation within any custom `TemplateCache` or `TemplateLoader` implementations to reject absolute paths, `.` or `..` segments, or paths escaping the intended cache root, as suggested in GHSA-f44v-7qgw-9gh9.

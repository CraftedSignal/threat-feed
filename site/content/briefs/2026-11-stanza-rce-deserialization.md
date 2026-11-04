---
brief_id: brief-2026-11-03-stanza-rce-deserialization
event_id: brief-2026-11-03-stanza-rce-deserialization
revision: 2
activity_at: "2026-11-04T00:47:56Z"
revision_history:
  - revision: 2
    at: "2026-11-04T00:47:56Z"
    checksum: sha256:49f573ef0310b5268f53ac408f793020dea2fe98ac47dd450e41d7bda0d133b6
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115878&utm_source=rss&utm_medium=rss
title: 'Stanza: RCE via pickle deserialization in lemmatizer (CVE-2026-115878)'
slug: 2026-11-stanza-rce-deserialization
description: Stanza version 1.14.0 is vulnerable to remote code execution (RCE) because the lemmatizer component processes a gzip-compressed pickle stream via an unrestricted pickle.loads() call during pipeline initialization.
date: "2026-11-03T22:15:37Z"
lastmod: "2026-11-04T00:47:14Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-115878&utm_source=rss&utm_medium=rss
products:
  - Stanza 1.14.0 (< 1.15.0)
cves:
  - id: CVE-2026-115878
    cvss: 7.8
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-gh9r-c94j-cmp5
  - https://sploitus.com/exploit?id=CVE-2026-115878&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-04T00:47:14Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115878&utm_source=rss&utm_medium=rss
---

Stanza version 1.14.0 contains a vulnerability where the lemmatizer component processes an embedded pickle stream without restriction. While the initial model load uses `torch.load(weights_only=True)`, the internal `dicts` field (a gzip-compressed pickle) is extracted and passed to an unrestricted `pickle.loads()` function. An attacker supplying a crafted lemma checkpoint can execute arbitrary code with the privileges of the process loading the pipeline. This vulnerability is triggered during `stanza.Pipeline` construction.

## Attack Mechanism

1. Stanza's `Trainer.load` performs `torch.load(weights_only=True)`. The outer `weights_only` check passes because the payload is hidden as `bytes` in the `dicts` field.
2. `Trainer.load` invokes `_unpack_pos_dict` with the `dicts` bytes.
3. `_unpack_pos_dict` decompresses the gzip stream and executes `pickle.loads()`.
4. Execution is confirmed end-to-end where a crafted checkpoint returning `os.system` via `__reduce__` successfully executes the command at load time.

## Impact

Successful exploitation allows for arbitrary code execution on the system running the Stanza pipeline. This occurs at initialization time before any processing or inference is performed.

## Recommendation

Patch Stanza by replacing the `pickle.loads()` call in `stanza/models/lemma/trainer.py` with a restricted unpickler that only allows primitive types.

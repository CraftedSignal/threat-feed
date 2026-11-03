---
brief_id: brief-2026-11-03-stanza-rce-deserialization
event_id: brief-2026-11-03-stanza-rce-deserialization
revision: 1
activity_at: "2026-11-03T22:15:37Z"
title: 'Stanza: RCE via pickle deserialization in lemmatizer (CVE-2026-115878)'
slug: 2026-11-stanza-rce-deserialization
description: Stanza version 1.14.0 is vulnerable to remote code execution (RCE) because the lemmatizer component processes a gzip-compressed pickle stream via an unrestricted pickle.loads() call during pipeline initialization.
date: "2026-11-03T22:15:37Z"
type: advisory
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
products:
  - Stanza 1.14.0 (< 1.15.0)
cves:
  - id: CVE-2026-115878
    cvss: 7.8
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-gh9r-c94j-cmp5
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

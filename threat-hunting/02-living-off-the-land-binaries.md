# Hunt 02 — Living Off the Land Binaries (LOLBins)

| | |
|---|---|
| **Hypothesis** | Native, digitally-signed Windows utilities (`certutil`, `bitsadmin`, `mshta`) are being abused to download or decode a payload, evading detections that only look for unrecognized/external tools |
| **Data Source** | Windows Security Log, Event ID 4688 |
| **Result** | ⬜ Negative finding (documented clean baseline) |

## Why This Hunt

"Living off the land" attacks deliberately avoid introducing any new, flaggable binary to the target system — instead abusing tools that are already present, trusted, and digitally signed by Microsoft. `certutil -urlcache` can download a remote file disguised as a certificate operation; `bitsadmin /transfer` can do the same via the Background Intelligent Transfer Service; `mshta` can execute remote HTA/JavaScript payloads. None of these require installing anything an antivirus product would flag by file reputation alone.

## Hunt Query

```spl
index=wineventlog EventCode=4688
(Process_Command_Line="*certutil*-urlcache*" OR Process_Command_Line="*certutil*-decode*"
 OR Process_Command_Line="*bitsadmin*/transfer*" OR Process_Command_Line="*mshta*http*")
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
```

## Result

```
0 events
```

No matching activity was found across the lab's full telemetry history at the time of the hunt.

## Why This Negative Result Is Still Meaningful

An empty result here is the *expected* outcome given the lab's current attack history — none of the attacks executed against this environment (see [`detections/`](../detections)) used these specific LOLBins techniques. Recording this explicitly accomplishes two things:

1. It establishes a documented **clean baseline** — if this same query is re-run after a future incident and suddenly returns results, that's a meaningful change worth investigating, rather than an ambiguous "I don't know if this is normal for this environment."
2. It directly informed the exclusion logic later written into the [Registry Persistence detection](../detections/08-registry-persistence.md) — knowing which native tools are *not* currently appearing in this telemetry stream helped calibrate which process names could safely be treated as suspicious when they *do* appear in a persistence context.

## Disposition

No findings, no action required. Candidate for a follow-up hunt validation test (deliberately running a benign `certutil -urlcache` command, as was done for Hunt 01) to confirm detection coverage rather than just absence of activity — noted as a potential next step rather than completed here.

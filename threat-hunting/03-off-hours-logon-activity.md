# Hunt 03 — Off-Hours Logon Activity

| | |
|---|---|
| **Hypothesis** | A compromised account is being used to log on outside normal working hours, when legitimate human activity is unlikely |
| **Data Source** | Windows Security Log, Event ID 4624 |
| **Result** | ⬜ Negative finding — but only after correcting the query for a significant false-positive source |

## Why This Hunt

Time-of-day is a weak signal on its own, but a useful *pivot* during an investigation: an account that normally only ever logs on during business hours suddenly authenticating at 3 AM is worth a second look, even if nothing else about the logon looks unusual.

## First Pass — and a False-Positive Lesson

The initial query:

```spl
index=wineventlog EventCode=4624 Logon_Type IN (2,3,10)
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time, host, Account_Name, Logon_Type, Source_Network_Address
| sort -_time
```

returned **289 events** — which looked, at first glance, like a significant finding. Reviewing the actual account names, however, showed the results were almost entirely **machine accounts** (`LAB-DC1$`, `LAB-WS10$`) authenticating to each other as part of normal, continuous Active Directory background operation (replication, machine-account Kerberos renewal) — not human logons at all, and not meaningfully tied to "hours" in any human sense since machines don't keep a schedule.

## Corrected Hunt Query

```spl
index=wineventlog EventCode=4624 Logon_Type IN (2,3,10)
| where NOT match(Account_Name, "\$$")
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time, host, Account_Name, Logon_Type, Source_Network_Address
| sort -_time
```

Excluding accounts ending in `$` (the Windows convention for machine/computer accounts) removes this noise entirely and leaves only human user logons in scope.

## Result

```
0 events
```

With machine-account noise correctly excluded, no human account logged on outside the 06:00–22:00 window during the period examined.

## Why This Matters As a Documented Process, Not Just a Result

The value of this hunt isn't only "no off-hours logons were found" — it's the demonstrated discipline of **not accepting the first query's output at face value**. A raw count of 289 events could easily have been reported as a finding requiring follow-up, wasting investigation time on background AD chatter. Actually reading the account names before drawing a conclusion, and then explicitly re-running with the correction, is the difference between a hunt that produces a false lead and one that produces a trustworthy negative result.

## Disposition

No findings after correction. No further action required. The `\$$` exclusion pattern used here is reusable guidance for any future hunt or detection in this lab involving `Account_Name`.

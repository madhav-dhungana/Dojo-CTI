"""Service layer for dojo_epss.

* http.py             — shared requests session, retry/backoff, EpssFetchError.
* first_client.py     — FIRST.org REST client (every documented query pattern).
* csv_importer.py     — streaming download + parser for the daily CSV.
* cve_extractor.py    — extracts CVEs from a Finding (regex + Vulnerability_Id).
* epss_importer.py    — upserts EPSSCVERecord rows.
* finding_matcher.py  — matches CVE rows against Findings; writes match logs.
* finding_updater.py  — writes Finding.epss_score / .epss_percentile when allowed.
* scheduler.py        — full-sync sequencer + cache-based concurrency lock.

No service module ever lets an external API failure bubble up to a Django
view; every failure is wrapped in EpssFetchError and logged.
"""

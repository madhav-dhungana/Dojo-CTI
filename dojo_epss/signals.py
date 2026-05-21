"""Signal handlers (currently empty stub).

Reserved for future hooks:
  * post_save on dojo.Finding -> mark a not-yet-scanned EpssMatchLog row
    for that finding's CVEs (so the new column shows 'not checked').
  * post_save on EpssEntry -> queue a delta-match for any new CVEs.

We intentionally don't wire these up by default to keep this app's footprint
minimal. Operators can enable them via DOJO_EPSS = {'ENABLE_SIGNALS': True}.
"""

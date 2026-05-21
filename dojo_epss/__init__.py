"""dojo_epss — continuous threat monitoring library for DefectDojo.

A pluggable Django app that enriches existing DefectDojo Findings with
FIRST.org EPSS data, KEV status, and ransomware usage signals. It supports
manual runs, scheduled Celery dispatcher runs, audit logs, dashboard views,
and a Swagger-visible API endpoint.

The package is additive: it adds its own Django app, ``/epss/`` URL section,
sidebar entry, and Finding-list indicators. It never changes Finding status,
deduplication keys, SLA calculation, scanner imports, risk acceptance, or
notification behavior.

See ``README.md`` for installation and integration steps.
"""

default_app_config = "dojo_epss.apps.DojoEpssConfig"
__version__ = "0.2.0"

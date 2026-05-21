"""DEPRECATED — use ``dojo_epss.services.first_client`` instead.

This module is now a one-line re-export kept solely to avoid breaking
external imports during an upgrade from 0.1.x. It will be removed in a
future release.
"""

from .first_client import (  # noqa: F401
    EpssRow,
    FirstEPSSClient,
    FirstEPSSClient as EpssApiClient,  # historical alias
)

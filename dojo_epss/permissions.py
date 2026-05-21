"""Access control helpers.

Mirrors DefectDojo's ``SystemSettingsView.permission_check`` pattern:
configure-able actions require ``request.user.is_superuser``. View-only
pages are accessible to any authenticated user holding the
``dojo_epss.view_epss_dashboard`` permission (or staff/superuser).

We intentionally don't add to ``dojo.authorization.roles_permissions.Permissions``
(that would couple us to dojo's enum and risk ID collisions). Instead we use
the standard Django app-namespaced permission codenames:

  * dojo_epss.view_epssfetchsettings
  * dojo_epss.change_epssfetchsettings
  * dojo_epss.view_epss_dashboard
  * dojo_epss.run_epss_fetch
"""

from __future__ import annotations

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


# This function allows superusers only. This function needs a view function.
def superuser_required(view_fn):
    """Strict gate: superuser only. Used for settings page + manual triggers."""
    @wraps(view_fn)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied("EPSS configuration is restricted to superusers.")
        return view_fn(request, *args, **kwargs)
    return wrapper


# This function allows dashboard viewers. This function needs a permission name.
def view_or_perm(perm: str = "dojo_epss.view_epss_dashboard"):
    """Loose gate: superuser OR staff OR explicit permission."""
    def decorator(view_fn):
        @wraps(view_fn)
        @login_required
        def wrapper(request, *args, **kwargs):
            user = request.user
            if user.is_superuser or user.is_staff:
                return view_fn(request, *args, **kwargs)
            if perm and user.has_perm(perm):
                return view_fn(request, *args, **kwargs)
            raise PermissionDenied(
                "EPSS pages require staff role or the dojo_epss.view_epss_dashboard permission.",
            )
        return wrapper
    return decorator

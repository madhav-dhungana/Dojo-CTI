"""Django AppConfig for dojo_epss.

Heavy imports happen lazily inside ``ready()`` so a fresh ``manage.py`` shell
or ``makemigrations`` invocation never imports ``dojo`` at app-load time.
"""

from django.apps import AppConfig


class DojoEpssConfig(AppConfig):
    name = "dojo_epss"
    label = "dojo_epss"
    verbose_name = "EPSS Enrichment for DefectDojo"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:  # pragma: no cover - import side-effect only
        try:
            from . import signals  # noqa: F401
        except Exception:  # pylint: disable=broad-except
            # Never let signal-import failures break worker boot.
            pass

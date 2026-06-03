from django.apps import AppConfig


class FakeDojoConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "dojo_epss.tests.fake_dojo"
    label = "dojo"

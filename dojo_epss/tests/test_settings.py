"""Standalone Django settings for dojo_epss pytest runs."""

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "dojo_epss.tests.fake_dojo",
    "dojo_epss",
]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
ROOT_URLCONF = "dojo_epss.urls"
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
USE_TZ = True
TIME_ZONE = "UTC"
SECRET_KEY = "dojo-epss-tests"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": []},
}]

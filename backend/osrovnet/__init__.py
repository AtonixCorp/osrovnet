# Ensure the celery app is loaded when Django starts
from .celery import app as celery_app  # noqa


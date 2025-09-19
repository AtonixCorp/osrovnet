from django.core.management.base import BaseCommand
from django.conf import settings
from pathlib import Path
import sys

class Command(BaseCommand):
    help = 'Check frontend build artefacts and print relevant Django settings paths'

    def handle(self, *args, **options):
        base_dir = Path(settings.BASE_DIR)
        repo_root = base_dir.parent
        frontend_build = repo_root / 'frontend' / 'build' / 'index.html'
        static_dir = repo_root / 'frontend' / 'build' / 'static'

        self.stdout.write('Frontend build check')
        self.stdout.write('---------------------')
        self.stdout.write(f'BASE_DIR: {settings.BASE_DIR}')
        self.stdout.write(f'REPO_ROOT: {repo_root}')
        self.stdout.write(f'TEMPLATES DIRS: {settings.TEMPLATES[0].get("DIRS", [])}')
        self.stdout.write(f'STATIC_ROOT: {settings.STATIC_ROOT}')
        self.stdout.write(f'STATICFILES_DIRS: {getattr(settings, "STATICFILES_DIRS", [])}')

        if frontend_build.exists():
            self.stdout.write(self.style.SUCCESS(f'Found frontend build index at: {frontend_build}'))
        else:
            self.stdout.write(self.style.WARNING(f'frontend build index NOT found at: {frontend_build}'))

        if static_dir.exists():
            self.stdout.write(self.style.SUCCESS(f'Found frontend static dir at: {static_dir}'))
        else:
            self.stdout.write(self.style.WARNING(f'frontend static dir NOT found at: {static_dir}'))

        # exit code non-zero when missing so CI can fail fast
        if not frontend_build.exists() or not static_dir.exists():
            sys.exit(2)

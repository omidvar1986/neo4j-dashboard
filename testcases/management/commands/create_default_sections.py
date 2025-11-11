from django.core.management.base import BaseCommand
from testcases.models import Section


class Command(BaseCommand):
    help = 'Create default test case sections'

    def handle(self, *args, **options):
        default_sections = [
            'Trade',
            'CoreProduct',
            'Core Product',
            'Core Services',
            'User',
            'Nobify',
            'Nobifi',
            'Others',
        ]
        
        created_count = 0
        for section_name in default_sections:
            section, created = Section.objects.get_or_create(name=section_name)
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f'Created section: {section_name}'))
            else:
                self.stdout.write(self.style.WARNING(f'Section already exists: {section_name}'))
        
        self.stdout.write(self.style.SUCCESS(f'\nCreated {created_count} new sections.'))


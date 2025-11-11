from mongoengine import Document, EmbeddedDocument, fields
from django.contrib.auth import get_user_model
from django.conf import settings
from datetime import datetime

User = get_user_model()


class Section(Document):
    """Test case sections/categories"""
    name = fields.StringField(max_length=200, required=True)
    parent = fields.ReferenceField('self', null=True, blank=True)
    description = fields.StringField(blank=True)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)

    meta = {
        'collection': 'sections',
        'indexes': [('name', 'parent')],  # Compound index for unique name per parent
        'ordering': ['name']
    }
    
    def clean(self):
        """Ensure name is unique within the same parent"""
        if self.name:
            # Check if another section with same name and parent exists
            # Handle both None parent and ReferenceField parent comparison
            if self.parent is None:
                query = Section.objects(name=self.name, parent__exists=False)
            else:
                query = Section.objects(name=self.name, parent=self.parent)
            
            # Exclude current document if it has an ID (for updates)
            if self.id:
                query = query.filter(id__ne=self.id)
            
            if query.count() > 0:
                from mongoengine.errors import ValidationError
                raise ValidationError(f'A section with name "{self.name}" already exists in this parent.')

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        self.clean()  # Validate before saving
        return super().save(*args, **kwargs)


class TestStep(EmbeddedDocument):
    """Individual test steps for a test case"""
    step_number = fields.IntField(required=True)
    description = fields.StringField(required=True)
    expected_result = fields.StringField(required=True)
    created_at = fields.DateTimeField(default=datetime.utcnow)


class TestCase(Document):
    """Test case model"""
    TYPE_CHOICES = [
        ('Functional', 'Functional'),
        ('Regression', 'Regression'),
        ('Smoke', 'Smoke'),
        ('Sanity', 'Sanity'),
        ('Other', 'Other'),
    ]

    PRIORITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    AUTOMATION_TYPE_CHOICES = [
        ('None', 'None'),
        ('Automated', 'Automated'),
        ('Manual', 'Manual'),
    ]

    title = fields.StringField(max_length=500, required=True)
    section = fields.ReferenceField(Section, required=True)
    template = fields.StringField(max_length=100, default='Test Case (Steps)')
    type = fields.StringField(max_length=50, choices=TYPE_CHOICES, default='Other')
    priority = fields.StringField(max_length=50, choices=PRIORITY_CHOICES, default='Medium')
    estimate = fields.StringField(max_length=50, blank=True)
    automation_type = fields.StringField(max_length=50, choices=AUTOMATION_TYPE_CHOICES, default='None')
    labels = fields.StringField(max_length=500, blank=True, help_text="Comma-separated labels")
    preconditions = fields.StringField(blank=True)
    steps = fields.ListField(fields.EmbeddedDocumentField(TestStep), default=list)
    created_by_id = fields.IntField(null=True)  # Store user ID as integer
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    is_deleted = fields.BooleanField(default=False)

    meta = {
        'collection': 'test_cases',
        'indexes': ['section', 'created_at', 'is_deleted'],
        'ordering': ['-created_at']
    }

    def __str__(self):
        section_name = self.section.name if self.section else 'No Section'
        return f"{self.title} ({section_name})"

    def get_labels_list(self):
        """Return labels as a list"""
        if self.labels:
            return [label.strip() for label in self.labels.split(',')]
        return []

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)

    @property
    def created_by(self):
        """Get the user who created this test case"""
        if self.created_by_id:
            try:
                return User.objects.get(id=self.created_by_id)
            except User.DoesNotExist:
                return None
        return None

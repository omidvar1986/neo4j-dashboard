from mongoengine import Document, EmbeddedDocument, fields
from django.contrib.auth import get_user_model
from django.conf import settings
from datetime import datetime

User = get_user_model()


class ChangeHistory(Document):
    """Track all changes to test cases and sections"""
    ACTION_CHOICES = [
        ('created', 'Created'),
        ('updated', 'Updated'),
        ('deleted', 'Deleted'),
    ]
    
    ENTITY_TYPES = [
        ('test_case', 'Test Case'),
        ('section', 'Section'),
    ]
    
    entity_type = fields.StringField(max_length=20, choices=ENTITY_TYPES, required=True)
    entity_id = fields.StringField(required=True)  # Store as string for flexibility
    action = fields.StringField(max_length=20, choices=ACTION_CHOICES, required=True)
    user_id = fields.IntField(required=True)  # Store user ID as integer
    timestamp = fields.DateTimeField(default=datetime.utcnow)
    description = fields.StringField(blank=True)  # Optional description of what changed
    
    meta = {
        'collection': 'change_history',
        'indexes': [
            ('entity_type', 'entity_id'),
            'timestamp',
            'user_id',
        ],
        'ordering': ['-timestamp']
    }
    
    @property
    def user(self):
        """Get the user object"""
        try:
            return User.objects.get(id=self.user_id)
        except User.DoesNotExist:
            return None
    
    def get_action_display(self):
        """Get the display name for the action"""
        action_map = dict(self.ACTION_CHOICES)
        return action_map.get(self.action, self.action.title())
    
    def __str__(self):
        user_name = self.user.username if self.user else f"User {self.user_id}"
        return f"{user_name} {self.action} {self.entity_type} {self.entity_id} at {self.timestamp}"


class SectionPermission(Document):
    """Permissions for users to edit/delete sections"""
    user_id = fields.IntField(required=True)  # Store user ID as integer
    can_edit = fields.BooleanField(default=False)
    can_delete = fields.BooleanField(default=False)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)

    meta = {
        'collection': 'section_permissions',
        'indexes': ['user_id'],
        'ordering': ['-created_at']
    }
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
    
    @property
    def user(self):
        """Get the user object"""
        try:
            return User.objects.get(id=self.user_id)
        except User.DoesNotExist:
            return None
    
    def __str__(self):
        try:
            user = User.objects.get(id=self.user_id)
            permissions = []
            if self.can_edit:
                permissions.append('Edit')
            if self.can_delete:
                permissions.append('Delete')
            return f"{user.username} - {', '.join(permissions) if permissions else 'No permissions'}"
        except User.DoesNotExist:
            return f"User {self.user_id} - Invalid"


class Section(Document):
    """Test case sections/categories"""
    name = fields.StringField(max_length=200, required=True)
    parent = fields.ReferenceField('self', null=True, blank=True)
    description = fields.StringField(blank=True)
    created_by_id = fields.IntField(null=True)  # Store user ID as integer
    updated_by_id = fields.IntField(null=True)  # Store user ID as integer
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
    
    @property
    def created_by(self):
        """Get the user who created this section"""
        if self.created_by_id:
            try:
                return User.objects.get(id=self.created_by_id)
            except User.DoesNotExist:
                return None
        return None
    
    @property
    def updated_by(self):
        """Get the user who last updated this section"""
        if self.updated_by_id:
            try:
                return User.objects.get(id=self.updated_by_id)
            except User.DoesNotExist:
                return None
        return None


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
    description = fields.StringField(blank=True, help_text="Description of what this test case does")
    preconditions = fields.StringField(blank=True)
    steps = fields.ListField(fields.EmbeddedDocumentField(TestStep), default=list)
    created_by_id = fields.IntField(null=True)  # Store user ID as integer
    updated_by_id = fields.IntField(null=True)  # Store user ID as integer
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
    
    @property
    def updated_by(self):
        """Get the user who last updated this test case"""
        if self.updated_by_id:
            try:
                return User.objects.get(id=self.updated_by_id)
            except User.DoesNotExist:
                return None
        return None

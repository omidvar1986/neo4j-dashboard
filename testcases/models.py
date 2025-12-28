from mongoengine import Document, EmbeddedDocument, fields
from django.contrib.auth import get_user_model
from django.conf import settings
from datetime import datetime
from pymongo.errors import OperationFailure

User = get_user_model()


class Project(Document):
    """Test case project - allows multiple teams to have separate projects"""
    name = fields.StringField(max_length=200, required=True, unique=True)
    description = fields.StringField(blank=True, max_length=1000)  # Max 1000 characters
    is_active = fields.BooleanField(default=True)
    created_by_id = fields.IntField(null=True)  # Store user ID as integer
    updated_by_id = fields.IntField(null=True)  # Store user ID as integer
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'projects',
        'indexes': ['name', 'is_active', 'created_at'],
        'ordering': ['name']
    }
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
    
    @property
    def created_by(self):
        """Get the user who created this project"""
        if self.created_by_id:
            try:
                return User.objects.get(id=self.created_by_id)
            except User.DoesNotExist:
                return None
        return None
    
    @property
    def updated_by(self):
        """Get the user who last updated this project"""
        if self.updated_by_id:
            try:
                return User.objects.get(id=self.updated_by_id)
            except User.DoesNotExist:
                return None
        return None
    
    def get_test_case_count(self):
        """Get count of test cases in this project"""
        from .models import TestCase
        return TestCase.objects(project=self, is_deleted=False).count()
    
    def get_section_count(self):
        """Get count of sections in this project"""
        from .models import Section
        return Section.objects(project=self).count()
    
    def get_active_test_runs_count(self):
        """Get count of active test runs (placeholder for future implementation)"""
        return 0
    
    def get_active_milestones_count(self):
        """Get count of active milestones (placeholder for future implementation)"""
        return 0


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
        ('project', 'Project'),
    ]
    
    entity_type = fields.StringField(max_length=20, choices=ENTITY_TYPES, required=True)
    entity_id = fields.StringField(required=True)  # Store as string for flexibility
    action = fields.StringField(max_length=20, choices=ACTION_CHOICES, required=True)
    user_id = fields.IntField(required=True)  # Store user ID as integer
    timestamp = fields.DateTimeField(default=datetime.utcnow)
    description = fields.StringField(blank=True, max_length=1000)  # Max 1000 characters  # Optional description of what changed
    
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
    project = fields.ReferenceField(Project, required=True)
    name = fields.StringField(max_length=200, required=True)
    parent = fields.ReferenceField('self', null=True, blank=True)
    description = fields.StringField(blank=True, max_length=1000)  # Max 1000 characters
    created_by_id = fields.IntField(null=True)  # Store user ID as integer
    updated_by_id = fields.IntField(null=True)  # Store user ID as integer
    created_at = fields.DateTimeField(default=datetime.utcnow)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    order = fields.IntField(default=0)

    meta = {
        'collection': 'sections',
        'indexes': [
            {
                'fields': ['project', 'parent', 'name'],
                'unique': True,
                'name': 'project_parent_name_unique'
            },
            # Leave unnamed so MongoDB reuses existing project_1 index if present
            {'fields': ['project']}
        ],
        'ordering': ['order', 'name']
    }
    
    def clean(self):
        """Ensure name is unique within the same parent and project"""
        if self.name and self.project:
            # Check if another section with same name, parent, and project exists
            # Handle both None parent and ReferenceField parent comparison
            if self.parent is None:
                query = Section.objects(project=self.project, name=self.name, parent__exists=False)
            else:
                query = Section.objects(project=self.project, name=self.name, parent=self.parent)
            
            # Exclude current document if it has an ID (for updates)
            if self.id:
                query = query.filter(id__ne=self.id)
            
            if query.count() > 0:
                from mongoengine.errors import ValidationError
                raise ValidationError(f'A section with name "{self.name}" already exists in this parent within the same project.')

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


def ensure_section_indexes():
    """Ensure MongoDB indexes for sections are project-scoped (drop legacy global unique)."""
    collection = Section._get_collection()
    indexes = collection.index_information()
    compound_key = [('project', 1), ('parent', 1), ('name', 1)]
    
    # Drop legacy global unique index on name if it exists
    legacy_index_name = None
    for name, info in indexes.items():
        if info.get('key') == [('name', 1)] and info.get('unique'):
            legacy_index_name = name
            break
    
    if legacy_index_name:
        try:
            collection.drop_index(legacy_index_name)
        except Exception:
            pass
    
    # Drop conflicting compound indexes that reuse the same key but have different names/options
    for name, info in indexes.items():
        if info.get('key') == compound_key and (
            info.get('name') != 'project_parent_name_unique' or not info.get('unique')
        ):
            try:
                collection.drop_index(name)
            except Exception:
                pass
    
    # Ensure the new compound unique index exists
    try:
        collection.create_index(
            compound_key,
            unique=True,
            name='project_parent_name_unique',
            background=True,
        )
    except OperationFailure as exc:
        # If another process recreated the same index concurrently, ignore the error
        if exc.code != 85:
            raise

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

    project = fields.ReferenceField(Project, required=True)
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
    order = fields.IntField(default=0)

    meta = {
        'collection': 'test_cases',
        'indexes': [('project', 'section'), 'project', 'section', 'created_at', 'is_deleted'],
        'ordering': ['order', '-created_at']
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


class TestRunResult(EmbeddedDocument):
    """Test result for a test case in a test run"""
    STATUS_CHOICES = [
        ('untested', 'Untested'),
        ('passed', 'Passed'),
        ('blocked', 'Blocked'),
        ('retest', 'Retest'),
        ('failed', 'Failed'),
    ]
    
    test_case = fields.ReferenceField('TestCase', required=True)
    status = fields.StringField(max_length=20, choices=STATUS_CHOICES, default='untested')
    assigned_to_id = fields.IntField(null=True)  # Store user ID as integer
    comment = fields.StringField(blank=True)
    step_results = fields.DictField(default=dict)  # Store step-level results: {step_number: status}
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
    
    @property
    def assigned_to(self):
        """Get the user assigned to this test result"""
        if self.assigned_to_id:
            try:
                return User.objects.get(id=self.assigned_to_id)
            except User.DoesNotExist:
                return None
        return None


class TestRun(Document):
    """Test run model - groups test cases for execution"""
    INCLUSION_TYPE_CHOICES = [
        ('all', 'Include all test cases'),
        ('specific', 'Select specific test cases'),
        ('dynamic', 'Dynamic Filtering'),
    ]
    
    project = fields.ReferenceField(Project, required=True)
    name = fields.StringField(max_length=500, required=True)
    description = fields.StringField(blank=True, max_length=1000)  # Max 1000 characters
    references = fields.StringField(blank=True, help_text="Reference IDs to external tickets")
    milestone_id = fields.StringField(blank=True)  # Can reference a milestone if implemented
    assigned_to_id = fields.IntField(null=True)  # Store user ID as integer
    start_date = fields.DateTimeField(null=True)
    end_date = fields.DateTimeField(null=True)
    inclusion_type = fields.StringField(max_length=20, choices=INCLUSION_TYPE_CHOICES, default='all')
    test_case_ids = fields.ListField(fields.StringField(), default=list)  # List of test case IDs for 'specific' type
    filter_criteria = fields.DictField(default=dict)  # For 'dynamic' type filtering
    results = fields.ListField(fields.EmbeddedDocumentField(TestRunResult), default=list)
    is_closed = fields.BooleanField(default=False)
    created_by_id = fields.IntField(null=True)  # Store user ID as integer
    updated_by_id = fields.IntField(null=True)  # Store user ID as integer
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'test_runs',
        'indexes': ['project', 'is_closed', 'created_at', 'created_by_id'],
        'ordering': ['-created_at']
    }
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
    
    @property
    def created_by(self):
        """Get the user who created this test run"""
        if self.created_by_id:
            try:
                return User.objects.get(id=self.created_by_id)
            except User.DoesNotExist:
                return None
        return None
    
    @property
    def updated_by(self):
        """Get the user who last updated this test run"""
        if self.updated_by_id:
            try:
                return User.objects.get(id=self.updated_by_id)
            except User.DoesNotExist:
                return None
        return None
    
    @property
    def assigned_to(self):
        """Get the user assigned to this test run"""
        if self.assigned_to_id:
            try:
                return User.objects.get(id=self.assigned_to_id)
            except User.DoesNotExist:
                return None
        return None
    
    def get_test_cases(self):
        """Get all test cases included in this test run"""
        import logging
        logger = logging.getLogger(__name__)
        
        # Import TestCase - it's defined earlier in this same file
        # We need to reference it by name to avoid circular imports
        from bson import ObjectId
        
        logger.info(f"[GET_TEST_CASES] Starting for test run {self.id}, inclusion_type={self.inclusion_type}, project={self.project.id if self.project else 'None'}")
        print(f"[GET_TEST_CASES] Starting for test run {self.id}, inclusion_type={self.inclusion_type}, project={self.project.id if self.project else 'None'}")
        
        # Get TestCase class from the module's namespace
        # Since TestCase is defined in the same module, we can access it directly
        import sys
        current_module = sys.modules[__name__]
        TestCase = getattr(current_module, 'TestCase')
        
        if not TestCase:
            logger.error(f"[GET_TEST_CASES] ERROR: TestCase class not found!")
            print(f"[GET_TEST_CASES] ERROR: TestCase class not found!")
            raise ImportError("TestCase class not found in models module")
        
        logger.info(f"[GET_TEST_CASES] TestCase class found: {TestCase}")
        print(f"[GET_TEST_CASES] TestCase class found: {TestCase}")
        
        if self.inclusion_type == 'all':
            logger.info(f"[GET_TEST_CASES] Inclusion type is 'all', querying all test cases for project {self.project.id}")
            print(f"[GET_TEST_CASES] Inclusion type is 'all', querying all test cases for project {self.project.id}")
            queryset = TestCase.objects(project=self.project, is_deleted=False).order_by('section', 'title')
            count = queryset.count()
            logger.info(f"[GET_TEST_CASES] Found {count} test cases in project")
            print(f"[GET_TEST_CASES] Found {count} test cases in project")
            return queryset
        elif self.inclusion_type == 'specific':
            logger.info(f"[GET_TEST_CASES] Inclusion type is 'specific', test_case_ids: {self.test_case_ids}")
            print(f"[GET_TEST_CASES] Inclusion type is 'specific', test_case_ids: {self.test_case_ids}")
            # Convert string IDs to ObjectIds
            if not self.test_case_ids:
                logger.warning(f"[GET_TEST_CASES] No test_case_ids provided, returning empty queryset")
                print(f"[GET_TEST_CASES] No test_case_ids provided, returning empty queryset")
                return TestCase.objects.none()  # Return empty queryset if no IDs
            
            # Handle both list of strings and comma-separated string
            if isinstance(self.test_case_ids, str):
                # If it's a string, split by comma
                id_list = [id.strip() for id in self.test_case_ids.split(',') if id.strip()]
            else:
                # If it's already a list
                id_list = self.test_case_ids
            
            logger.info(f"[GET_TEST_CASES] Processed id_list: {id_list}")
            print(f"[GET_TEST_CASES] Processed id_list: {id_list}")
            
            object_ids = []
            for tc_id in id_list:
                if ObjectId.is_valid(str(tc_id)):
                    object_ids.append(ObjectId(str(tc_id)))
                else:
                    logger.warning(f"[GET_TEST_CASES] WARNING: Invalid ObjectId: {tc_id}")
                    print(f"[GET_TEST_CASES] WARNING: Invalid ObjectId: {tc_id}")
            
            logger.info(f"[GET_TEST_CASES] Valid ObjectIds: {object_ids}")
            print(f"[GET_TEST_CASES] Valid ObjectIds: {object_ids}")
            
            if not object_ids:
                logger.warning(f"[GET_TEST_CASES] No valid ObjectIds, returning empty queryset")
                print(f"[GET_TEST_CASES] No valid ObjectIds, returning empty queryset")
                return TestCase.objects.none()
            
            queryset = TestCase.objects(id__in=object_ids, project=self.project, is_deleted=False).order_by('section', 'title')
            count = queryset.count()
            logger.info(f"[GET_TEST_CASES] Found {count} test cases matching specific IDs")
            print(f"[GET_TEST_CASES] Found {count} test cases matching specific IDs")
            return queryset
        else:  # dynamic
            logger.info(f"[GET_TEST_CASES] Inclusion type is 'dynamic'")
            print(f"[GET_TEST_CASES] Inclusion type is 'dynamic'")
            # Apply filter criteria (simplified for now)
            query = TestCase.objects(project=self.project, is_deleted=False)
            # Add filter logic here based on filter_criteria
            queryset = query.order_by('section', 'title')
            count = queryset.count()
            logger.info(f"[GET_TEST_CASES] Found {count} test cases with dynamic filter")
            print(f"[GET_TEST_CASES] Found {count} test cases with dynamic filter")
            return queryset
    
    def get_results_summary(self):
        """Get summary of test results"""
        # Get total number of test cases in this run
        try:
            test_cases = self.get_test_cases()
            # Convert to list to count properly
            if hasattr(test_cases, '__iter__') and not isinstance(test_cases, (list, tuple)):
                test_cases_list = list(test_cases)
            else:
                test_cases_list = test_cases if isinstance(test_cases, list) else list(test_cases)
            total_test_cases = len(test_cases_list)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error getting test cases for summary in test run {self.id}: {str(e)}")
            total_test_cases = len(self.results)
        
        # Count statuses from results
        passed = sum(1 for r in self.results if r.status == 'passed')
        blocked = sum(1 for r in self.results if r.status == 'blocked')
        retest = sum(1 for r in self.results if r.status == 'retest')
        failed = sum(1 for r in self.results if r.status == 'failed')
        untested_results = sum(1 for r in self.results if r.status == 'untested')
        
        # Calculate untested: test cases without results + results marked as untested
        # Test cases without results are considered untested
        test_cases_with_results = len(self.results)
        test_cases_without_results = total_test_cases - test_cases_with_results
        untested = test_cases_without_results + untested_results
        
        # Use total_test_cases as the total, not len(self.results)
        total = total_test_cases
        
        passed_percent = int((passed / total) * 100) if total > 0 else 0
        
        return {
            'total': total,
            'passed': passed,
            'blocked': blocked,
            'retest': retest,
            'failed': failed,
            'untested': untested,
            'passed_percent': passed_percent,
        }
    
    def update_results_for_test_cases(self):
        """Update results list when test cases are added/removed"""
        import logging
        import traceback
        logger = logging.getLogger(__name__)
        
        logger.info(f"[UPDATE_RESULTS] Starting for test run {self.id}")
        print(f"[UPDATE_RESULTS] Starting for test run {self.id}")
        logger.info(f"[UPDATE_RESULTS] Current results count: {len(self.results)}")
        print(f"[UPDATE_RESULTS] Current results count: {len(self.results)}")
        logger.info(f"[UPDATE_RESULTS] Inclusion type: {self.inclusion_type}")
        print(f"[UPDATE_RESULTS] Inclusion type: {self.inclusion_type}")
        
        try:
            test_cases = self.get_test_cases()
            logger.info(f"[UPDATE_RESULTS] Got test_cases: {type(test_cases)}")
            print(f"[UPDATE_RESULTS] Got test_cases: {type(test_cases)}")
            
            # Convert to list if it's a queryset
            if hasattr(test_cases, '__iter__') and not isinstance(test_cases, (list, tuple)):
                logger.info(f"[UPDATE_RESULTS] Converting queryset to list...")
                print(f"[UPDATE_RESULTS] Converting queryset to list...")
                test_cases = list(test_cases)
                logger.info(f"[UPDATE_RESULTS] Converted to list, length: {len(test_cases)}")
                print(f"[UPDATE_RESULTS] Converted to list, length: {len(test_cases)}")
            
            logger.info(f"[UPDATE_RESULTS] Total test cases to process: {len(test_cases)}")
            print(f"[UPDATE_RESULTS] Total test cases to process: {len(test_cases)}")
            logger.info(f"Updating results for test run {self.id}: found {len(test_cases)} test cases (inclusion_type={self.inclusion_type})")
            
            existing_result_map = {str(r.test_case.id): r for r in self.results}
            logger.info(f"[UPDATE_RESULTS] Existing results map has {len(existing_result_map)} entries")
            print(f"[UPDATE_RESULTS] Existing results map has {len(existing_result_map)} entries")
            
            new_results = []
            for idx, test_case in enumerate(test_cases):
                test_case_id = str(test_case.id)
                logger.info(f"[UPDATE_RESULTS] Processing test case {idx+1}/{len(test_cases)}: {test_case_id} - {test_case.title[:50]}")
                print(f"[UPDATE_RESULTS] Processing test case {idx+1}/{len(test_cases)}: {test_case_id} - {test_case.title[:50]}")
                
                if test_case_id in existing_result_map:
                    # Keep existing result
                    logger.info(f"[UPDATE_RESULTS] Keeping existing result for {test_case_id}")
                    print(f"[UPDATE_RESULTS] Keeping existing result for {test_case_id}")
                    new_results.append(existing_result_map[test_case_id])
                else:
                    # Create new result
                    logger.info(f"[UPDATE_RESULTS] Creating new result for {test_case_id}")
                    print(f"[UPDATE_RESULTS] Creating new result for {test_case_id}")
                    new_result = TestRunResult(
                        test_case=test_case,
                        status='untested',
                        assigned_to_id=self.assigned_to_id
                    )
                    new_results.append(new_result)
                    logger.info(f"[UPDATE_RESULTS] Created TestRunResult with status='untested', assigned_to_id={self.assigned_to_id}")
                    print(f"[UPDATE_RESULTS] Created TestRunResult with status='untested', assigned_to_id={self.assigned_to_id}")
            
            logger.info(f"[UPDATE_RESULTS] Total new results: {len(new_results)}")
            print(f"[UPDATE_RESULTS] Total new results: {len(new_results)}")
            logger.info(f"Created {len(new_results)} results for test run {self.id}")
            
            self.results = new_results
            logger.info(f"[UPDATE_RESULTS] Set self.results, now saving...")
            print(f"[UPDATE_RESULTS] Set self.results, now saving...")
            self.save()
            logger.info(f"[UPDATE_RESULTS] Saved successfully! Results count: {len(self.results)}")
            print(f"[UPDATE_RESULTS] Saved successfully! Results count: {len(self.results)}")
            
            return len(new_results)
        except Exception as e:
            error_trace = traceback.format_exc()
            logger.error(f"[UPDATE_RESULTS] ERROR: {str(e)}")
            print(f"[UPDATE_RESULTS] ERROR: {str(e)}")
            logger.error(f"[UPDATE_RESULTS] TRACEBACK:\n{error_trace}")
            print(f"[UPDATE_RESULTS] TRACEBACK:\n{error_trace}")
            logger.error(f"Error in update_results_for_test_cases for test run {self.id}: {str(e)}\n{error_trace}")
            raise

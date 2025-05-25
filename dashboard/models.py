from django.db import models
from collections import defaultdict
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.utils import timezone
from django.contrib.auth.models import UserManager

class CustomUserManager(UserManager):
    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_approved', True) # Automatically approve superusers
        extra_fields.setdefault('role', 3) # Set default role to Admin (3) for superusers
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(username, email, password, **extra_fields)

class user(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        (1, 'Query User'),  # Can only access Predefined Queries and Explore Layers
        (2, 'Node User'),   # Can only access Add Nodes and Manual Query
        (3, 'Admin User'),  # Can access everything including Admin Queries and User Management
    ]
    
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        help_text=
            _("Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."),
        validators=[username_validator],
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email = models.EmailField(_("email address"), blank=True)
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=
            _("Designates whether this user should be treated as active. ")
            + _("Unselect this instead of deleting accounts."),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    role = models.IntegerField(choices=ROLE_CHOICES, default=1)
    is_approved = models.BooleanField(default=False, help_text="Designates whether the user has been approved by an admin.")

    objects = CustomUserManager()

    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["email", "role"]
    USERNAME_FIELD = "username"

    class Meta:
        app_label = 'dashboard'
        db_table = 'dashboard_user'
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = False # Set to False for concrete model
        swappable = 'AUTH_USER_MODEL'

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = "%s %s" % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def has_role(self, required_role):
        return self.role == required_role
    
    def can_access_predefined_queries(self):
        return self.role in [1, 3]
    
    def can_access_explore_layers(self):
        return self.role in [1, 3]
    
    def can_access_add_nodes(self):
        return self.role in [2, 3]
    
    def can_access_manual_queries(self):
        return self.role in [2, 3]
    
    def can_access_admin_queries(self):
        return self.role == 3

class AdminQuery(models.Model):
    title = models.CharField(max_length=200, verbose_name="Title")
    query_text = models.TextField(verbose_name="Query Text")
    created_by = models.CharField(max_length=100, verbose_name="Created By", default="Admin")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")
    is_active = models.BooleanField(default=True, verbose_name="Active")

    class Meta:
        verbose_name = "Admin Query"
        verbose_name_plural = "Admin Queries"

    def __str__(self):
        return self.title
    
    

class PredefinedQuery(models.Model):
    CATEGORY_CHOICES = [
        ('General', 'General'),
        ('Analysis', 'Analysis'),
        ('Maintenance', 'Maintenance'),
        # Add more as needed
    ]
    title = models.CharField(max_length=200, verbose_name="Title")
    query_text = models.TextField(verbose_name="Query Text")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='General')
    created_by = models.CharField(max_length=100, verbose_name="Created By", default="Admin")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")
    is_active = models.BooleanField(default=True, verbose_name="Active")

    class Meta:
        verbose_name = "Predefined Query"
        verbose_name_plural = "Predefined Queries"

    def __str__(self):
        return self.title

def predefined_queries(request):
    queries = PredefinedQuery.objects.filter(is_active=True)
    categories = defaultdict(list)
    for q in queries:
        categories[q.category].append(q)
    return render(request, 'dashboard/predefined_queries.html', {
        'categories': dict(categories)
    })

class TestResult(models.Model):
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=[
        ('PASS', 'Pass'),
        ('FAIL', 'Fail'),
        ('SKIP', 'Skip'),
    ])
    duration = models.FloatField()
    last_run = models.DateTimeField(auto_now=True)
    error_message = models.TextField(null=True, blank=True)
    test_file = models.CharField(max_length=255)
    line_number = models.IntegerField()

    class Meta:
        ordering = ['-last_run']

class ComponentDependency(models.Model):
    source = models.CharField(max_length=255)  # Component that depends on target
    target = models.CharField(max_length=255)  # Component that is depended upon
    dependency_type = models.CharField(max_length=50)  # e.g., 'import', 'call', 'reference'
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['source', 'target', 'dependency_type']

class TestCoverage(models.Model):
    file_path = models.CharField(max_length=255)
    coverage_percentage = models.FloatField()
    lines_covered = models.IntegerField()
    total_lines = models.IntegerField()
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_updated']
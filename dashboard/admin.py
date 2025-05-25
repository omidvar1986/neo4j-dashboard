from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import user, AdminQuery, PredefinedQuery, TestResult, ComponentDependency, TestCoverage

# Define a custom User admin
class CustomUserAdmin(UserAdmin):
    model = user
    # Add role and is_approved to the list display
    list_display = ('username', 'email', 'role', 'is_approved', 'is_staff')

    # Add role and is_approved to the fieldsets for editing
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('role', 'is_approved')}),
    )

# Unregister the default User model if it was registered (optional, but good practice)
try:
    admin.site.unregister(user)
except admin.sites.NotRegistered:
    pass

# Register your models here with the custom admin class
admin.site.register(user, CustomUserAdmin)

# Register other existing models
admin.site.register(AdminQuery)
admin.site.register(PredefinedQuery)
admin.site.register(TestResult)
admin.site.register(ComponentDependency)
admin.site.register(TestCoverage)
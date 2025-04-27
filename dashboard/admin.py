from django.contrib import admin
from .models import AdminQuery

@admin.register(AdminQuery)
class AdminQueryAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_by', 'created_at', 'is_active')
    list_filter = ('is_active', 'created_at')
    search_fields = ('title', 'query_text')
    date_hierarchy = 'created_at'
    ordering = ('-created_at',)
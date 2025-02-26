# dashboard/admin.py
from django.contrib import admin
from .models import SavedQuery, PredefinedQuery

@admin.register(SavedQuery)
class SavedQueryAdmin(admin.ModelAdmin):
    list_display = ('query', 'executed_at')
    list_filter = ('executed_at',)
    search_fields = ('query',)

@admin.register(PredefinedQuery)
class PredefinedQueryAdmin(admin.ModelAdmin):
    list_display = ('name', 'query')
    search_fields = ('name',)
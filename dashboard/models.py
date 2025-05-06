from django.db import models
from collections import defaultdict

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
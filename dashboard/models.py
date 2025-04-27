from django.db import models

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
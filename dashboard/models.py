from django.db import models

class SavedQuery(models.Model):
    query = models.TextField()
    executed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Query executed at {self.executed_at}"

    class Meta:
        ordering = ['-executed_at']

class PredefinedQuery(models.Model):
    name = models.CharField(max_length=100, unique=True)
    query = models.TextField()

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']
# security_agent/models.py
from django.db import models

class SecurityAlert(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=512)
    risk_score = models.FloatField()
    matched_tag = models.CharField(max_length=64, null=True, blank=True)
    details = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.timestamp} {self.path} score={self.risk_score}"

#store suspicious requests so now we  can review them
class SuspiciousPayload(models.Model):
    raw_text = models.TextField()
    threat_type = models.CharField(max_length=200, default="Unknown")
    vector = models.TextField()
    confirmed = models.BooleanField(default=False)  # <- this is required
    created_at = models.DateTimeField(auto_now_add=True)
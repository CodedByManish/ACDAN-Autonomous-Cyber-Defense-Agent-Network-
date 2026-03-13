from django.db import models

class ThreatAlert(models.Model):
    
    # Mapping Pydantic ThreatAlert to a Database Table
    timestamp = models.DateTimeField(auto_now_add=True)
    attack_type = models.CharField(max_length=100)
    source_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    risk_level = models.CharField(max_length=20, choices=[
        ('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')
    ])
    confidence = models.FloatField()
    threat_summary = models.TextField()
    status = models.CharField(max_length=20, default="OPEN")

    def __str__(self):
        return f"{self.attack_type} - {self.risk_level}"
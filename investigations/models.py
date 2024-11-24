# investigations/models.py
from django.db import models

class Investigation(models.Model):
    domain = models.CharField(max_length=255)
    whois_data = models.JSONField(null=True, blank=True)
    dns_data = models.JSONField(null=True, blank=True)
    traceroute_data = models.JSONField(null=True, blank=True)
    port_scan_data = models.JSONField(null=True, blank=True)
    ssl_cert_data = models.JSONField(null=True, blank=True)
    ai_assessment = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain

# investigations/serializers.py
from rest_framework import serializers
from .models import Investigation

class InvestigationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Investigation
        fields = '__all__'

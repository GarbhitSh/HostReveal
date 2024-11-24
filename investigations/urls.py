# investigations/urls.py
from django.urls import path
from .views import InvestigationView

urlpatterns = [
    path('investigate/', InvestigationView.as_view(), name='investigate'),
]

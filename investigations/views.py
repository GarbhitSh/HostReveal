# investigations/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Investigation
from .serializers import InvestigationSerializer
from .network_tools import get_whois, get_dns_records, perform_traceroute, analyze_ssl

class InvestigationView(APIView):
    def post(self, request):
        domain = request.data.get("domain")
        if not domain:
            return Response({"error": "Domain is required"}, status=400)

        investigation = Investigation.objects.create(domain=domain)

        # Perform analysis
        investigation.whois_data = get_whois(domain)
        investigation.dns_data = get_dns_records(domain)
        investigation.traceroute_data = perform_traceroute(domain)
        investigation.ssl_cert_data = analyze_ssl(domain)
        investigation.save()

        serializer = InvestigationSerializer(investigation)
        return Response(serializer.data)

    def get(self, request):
        investigations = Investigation.objects.all()
        serializer = InvestigationSerializer(investigations, many=True)
        return Response(serializer.data)

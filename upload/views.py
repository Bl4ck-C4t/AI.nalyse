from rest_framework import generics
from .models import Upload
from .serializers import UploadSerializer

class UploadView(generics.CreateAPIView):
    queryset = Upload.objects.all()
    serializer_class = UploadSerializer

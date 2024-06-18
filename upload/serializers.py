from rest_framework import serializers
import sys

# setting path
from .Thesis.classes.MainExecutor import CompleteScanner
from .models import Upload
import os


class UploadSerializer(serializers.ModelSerializer):
    vulns = serializers.SerializerMethodField()

    class Meta:
        model = Upload
        fields = ('file', 'vulns')

    def get_vulns(self, obj):
        scanner = CompleteScanner()
        print(obj.file.path)
        res = scanner.prettyScan("D:/Pycharm Projects/ThesisBackend/uploads/bof", verbose=2)
        # print(res)
        return res
from rest_framework import serializers
import sys

from .Thesis.classes.Exceptions import FileTypeException
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
        try:
            res = scanner.prettyScan("D:/Pycharm Projects/ThesisBackend/manage.py", verbose=2)
        except FileTypeException as e:
            raise serializers.ValidationError({"message": "Wrong file type"})
        # print(res)
        return res

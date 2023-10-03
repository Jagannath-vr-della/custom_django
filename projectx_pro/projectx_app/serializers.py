from rest_framework import serializers
from projectx_app import models


class ContentTypeSerializerCustom(serializers.Serializer):
    model_name = serializers.CharField(max_length=255)


class ContentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ContentType
        fields = "__all__"


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Roles
        fields = "__all__"


class RoleSerializerCustom(serializers.Serializer):
    ROLE_CHOICES = {
        ('ADMIN','ADMIN'),
        ('USER1','USER1'),
        ('USER2','USER2'),
    }
    role_name = serializers.ChoiceField(choices=ROLE_CHOICES)
from rest_framework import serializers
from projectx_app import models
from .models import *


class ContentTypeSerializerCustom(serializers.Serializer):
    model_name = serializers.CharField(max_length=255)


class ContentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PermissionGenerator
        fields = "__all__"


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Roles
        fields = "__all__"


class RoleSerializerCustom(serializers.Serializer):
    ROLE_CHOICES = {
        ('ADMIN','ADMIN'),
        ('USER1','USER1'),
        ('USER2','USER2'),
    }
    role_name = serializers.ChoiceField(choices=ROLE_CHOICES)


class RolePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        models = RolePermission
        fields = ('role','permission')


class SignupSerializerCustom(serializers.Serializer):
    user_name = serializers.CharField(max_length=200)
    password = serializers.CharField(max_length=200)
    email = serializers.CharField(max_length=200)
    role = serializers.CharField(max_length=200)


class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('user_name','email','password')


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'
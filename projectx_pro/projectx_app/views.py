# from drf_yasg.utils import swagger_auto_schema
from rest_framework.generics import CreateAPIView, RetrieveAPIView,DestroyAPIView,UpdateAPIView
# from rest_framework.authtoken.models import Token
from rest_framework import status
# from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from projectx_app import models,serializers,permission
from django.contrib.auth import hashers


class ContentType(CreateAPIView):
    serializer_class = serializers.ContentTypeSerializerCustom

    def post(self, request, *args, **kwargs):
        serializer_class = serializers.ContentTypeSerializer(data=request.data)
        if serializer_class.is_valid():
            serializer_class.save()
            permission.Permission.objects.create(app_name='projectx_app', model_name=serializer_class.data['model_name']
                                                 , content_name='create_' + str(serializer_class.data['model_name']),
                                      p_name='create_' + str(serializer_class.data['model_name']) + '_permission')
            permission.Permission.objects.create(app_name='projectx_app', model_name=str(serializer_class.data['model_name']), content_name='edit_' + str(serializer_class.data['model_name']),
                                      p_name='edit_' + str(serializer_class.data['model_name']) + '_permission')
            permission.Permission.objects.create(app_name='projectx_app', model_name=str(serializer_class.data['model_name']), content_name='view_' + str(serializer_class.data['model_name']),
                                      p_name='view_' + str(serializer_class.data['model_name']) + '_permission')
            permission.Permission.objects.create(app_name='projectx_app', model_name=str(serializer_class.data['model_name']), content_name='delete_' + str(serializer_class.data['model_name']),
                                      p_name='delete' + str(serializer_class.data['model_name']) + '_permission')
            data = {'status':"Success boss"}
            return Response(data)
        return Response("Failed Boss")


class AddRole(CreateAPIView):
    serializer_class = serializers.RoleSerializerCustom

    def post(self, request, *args, **kwargs):
        serializer_class = serializers.RoleSerializer(data=request.data)
        if serializer_class.is_valid():
            serializer_class.save()
            show = permission.Permission.objects.filter(content_name='view_User', model_name='User')
            add = permission.Permission.objects.filter(content_name='create_User', model_name='User')
            change = permission.Permission.objects.filter(content_name='edit_User', model_name='User')
            deleted = permission.Permission.objects.filter(content_name='delete_User', model_name='User')
            if serializer_class.data['role_name'] == "ADMIN":
                ADMIN = models.Roles.objects.filter('role_name')
                perm = models.RolePermission.objects.add(ADMIN,show)
                perm.save()
                models.RolePermission.objects.add(ADMIN,add)
                models.RolePermission.objects.add(ADMIN,change)
                models.RolePermission.objects.add(ADMIN,deleted)
            return Response("Role added boss")

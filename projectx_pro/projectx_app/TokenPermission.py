from django.db import models
from rest_framework import status
import secrets
from .models import User,UserRole,RolePermission  # Import your custom model
from datetime import datetime
from rest_framework import permissions
from .models import Token
from .models import Token
from rest_framework import permissions
from .models import UserRole, RolePermission, User


def generate_custom_model_token(custom_model_id):
    try:
        custom_model_instance = User.objects.get(user_id=custom_model_id)
        token = secrets.token_hex(20)
        Token.objects.create(user=custom_model_instance, key=token, created_at=datetime.now())
        return token
    except User.DoesNotExist:
        return None, {'error': 'Custom model not found'}, status.HTTP_404_NOT_FOUND


class TokenPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            authorization_header = request.META.get('HTTP_AUTHORIZATION', '')
            if authorization_header.startswith('Token '):
                token = authorization_header[len('Token '):]
                token_obj = Token.objects.get(key=token)
                user = token_obj.user_id
                if not user:
                    return False
                user_role = UserRole.objects.get(user=user)
                role = user_role.r_id
                perm = RolePermission.objects.filter(r=role).values('p_id')
                if request.method == 'POST':
                    return self.has_permission_for_post(perm)
                elif request.method == 'PUT':
                    return self.has_permission_for_put(perm)
                elif request.method == 'GET':
                    return self.has_permission_for_views(perm)
                elif request.method == 'DELETE':
                    return self.has_permission_for_delete(perm)

                return False
        except Exception as e:
            return e

    def has_permission_for_views(self, perm):
        for i in range(len(perm)):
            if 185 == perm[i]['p_id']:
                return True
        return False

    def has_permission_for_post(self, perm):
        for i in range(len(perm)):
            if 183 == perm[i]['p_id']:
                return True
        return False

    def has_permission_for_put(self, perm):
        for i in range(len(perm)):
            if 184 == perm[i]['p_id']:
                return True
        return False

    def has_permission_for_delete(self, perm):
        for i in range(len(perm)):
            if 186 == perm[i]['p_id']:
                return True
        return False
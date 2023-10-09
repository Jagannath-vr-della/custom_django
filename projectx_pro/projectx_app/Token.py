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


# class TokenPermissionView(permissions.BasePermission):
#     def has_permission(self, request, view):
#         try:
#             authorization_header = request.META.get('HTTP_AUTHORIZATION', '')
#             if authorization_header.startswith('Token '):
#                 _,token = authorization_header[len('Token '):]
#                 self.token = token
#                 us_id = Token.objects.get(key=token).user
#
#                 if not us_id:
#                     return False
#                 return self.has_permission_for_views(token, view)
#         except Exception as e:
#             return e
#
#     def has_permission_for_views(self, token, view):
#         us_id = Token.objects.get(key=token).user
#         role = UserRole.objects.get(user=us_id).r
#         perm = RolePermission.objects.get(r=role).p
#         if str(perm) == '185':
#             return True
#         return False
class TokenPermissionView(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            authorization_header = request.META.get('HTTP_AUTHORIZATION', '')

            if authorization_header.startswith('Token '):
                token = authorization_header[len('Token '):]
                token_obj = Token.objects.get(key=token)
                user = token_obj.user_id
                user_role = UserRole.objects.get(user=user)
                role = user_role.r_id
                perm = RolePermission.objects.filter(r=role).values('p_id')
                for i in range(len(perm)):
                    if 185 == perm[i]['p_id']:
                        return True
        except (Token.DoesNotExist, UserRole.DoesNotExist, RolePermission.DoesNotExist):
            return False


class TokenPermissionPost(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            authorization_header = request.META.get('HTTP_AUTHORIZATION', '')

            if authorization_header.startswith('Token '):
                token = authorization_header[len('Token '):]
                token_obj = Token.objects.get(key=token)
                user = token_obj.user_id
                user_role = UserRole.objects.get(user=user)
                role = user_role.r_id
                perm = RolePermission.objects.filter(r=role).values('p_id')
                for i in range(len(perm)):
                    if 183 == perm[i]['p_id']:
                        return True
        except (Token.DoesNotExist, UserRole.DoesNotExist, RolePermission.DoesNotExist):
            return False


class TokenPermissionPut(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            authorization_header = request.META.get('HTTP_AUTHORIZATION', '')

            if authorization_header.startswith('Token '):
                token = authorization_header[len('Token '):]
                token_obj = Token.objects.get(key=token)
                user = token_obj.user_id
                user_role = UserRole.objects.get(user=user)
                role = user_role.r_id
                perm = RolePermission.objects.filter(r=role).values('p_id')
                for i in range(len(perm)):
                    if 184 == perm[i]['p_id']:
                        return True
        except (Token.DoesNotExist, UserRole.DoesNotExist, RolePermission.DoesNotExist):
            return False


class TokenPermissionDelete(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            authorization_header = request.META.get('HTTP_AUTHORIZATION', '')

            if authorization_header.startswith('Token '):
                token = authorization_header[len('Token '):]
                token_obj = Token.objects.get(key=token)
                user = token_obj.user_id
                user_role = UserRole.objects.get(user=user)
                role = user_role.r_id
                perm = RolePermission.objects.filter(r=role).values('p_id')
                for i in range(len(perm)):
                    if 186 == perm[i]['p_id']:
                        return True
        except (Token.DoesNotExist, UserRole.DoesNotExist, RolePermission.DoesNotExist):
            return False
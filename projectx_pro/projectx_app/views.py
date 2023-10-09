from drf_yasg.utils import swagger_auto_schema
from rest_framework.generics import CreateAPIView, RetrieveAPIView, DestroyAPIView, UpdateAPIView
from django.contrib.auth.hashers import check_password
from rest_framework import status
from rest_framework.response import Response
from projectx_app import models, serializers, permission
from django.contrib.auth import hashers
from .permission import Permission
from django.apps import apps
from .Token import generate_custom_model_token,TokenPermissionPost,TokenPermissionPut,TokenPermissionView,TokenPermissionDelete
from .TokenPermission import TokenPermission


class PermissionGenerator(CreateAPIView):
    """This Api is used to Generate Permissions for models """
    serializer_class = serializers.ContentTypeSerializerCustom

    def post(self, request, *args, **kwargs):
        serializer_class = serializers.ContentTypeSerializer(data=request.data)
        if serializer_class.is_valid():
            mod = apps.get_models()
            for mod in mod:
                if mod.__name__ == request.data['model_name']:
                    serializer_class.save()
                    permission.Permission.objects.create(app_name='projectx_app', model_name=serializer_class.data['model_name']
                                                         , content_name='create_' + str(serializer_class.data['model_name']),
                                                         p_name='create_' + str(
                                                             serializer_class.data['model_name']) + '_permission')
                    permission.Permission.objects.create(app_name='projectx_app',
                                                         model_name=str(serializer_class.data['model_name']),
                                                         content_name='edit_' + str(serializer_class.data['model_name']),
                                                         p_name='edit_' + str(
                                                             serializer_class.data['model_name']) + '_permission')
                    permission.Permission.objects.create(app_name='projectx_app',
                                                         model_name=str(serializer_class.data['model_name']),
                                                         content_name='view_' + str(serializer_class.data['model_name']),
                                                         p_name='view_' + str(
                                                             serializer_class.data['model_name']) + '_permission')
                    permission.Permission.objects.create(app_name='projectx_app',
                                                         model_name=str(serializer_class.data['model_name']),
                                                         content_name='delete_' + str(serializer_class.data['model_name']),
                                                         p_name='delete_' + str(
                                                             serializer_class.data['model_name']) + '_permission')

                    return Response({'response_code': status.HTTP_200_OK,
                                     'message': "Permission Created",
                                     'status_flag': True,
                                     'status': "success",
                                     'error_details': None,
                                     'data': serializer_class.data})
                return Response("Failed Boss")


class AddRole(CreateAPIView):
    """This Api is used to Create Role and its Permissions """
    serializer_class = serializers.RoleSerializerCustom

    def post(self, request, *args, **kwargs):
        serializer_class = serializers.RoleSerializer(data=request.data)
        if serializer_class.is_valid():
            serializer_class.save()
            show = Permission.objects.get(p_name='view_Product_permission').p_id
            add = permission.Permission.objects.get(p_name='create_Product_permission').p_id
            change = permission.Permission.objects.get(p_name='edit_Product_permission').p_id
            deleted = permission.Permission.objects.get(p_name='delete_Product_permission').p_id
            if serializer_class.data['role_name'] == "ADMIN":
                role = serializer_class.data['r_id']
                models.RolePermission.objects.add(r_id=role, p_id=show)
                models.RolePermission.objects.add(r_id=role, p_id=add)
                models.RolePermission.objects.add(r_id=role, p_id=change)
                models.RolePermission.objects.add(r_id=role, p_id=deleted)
            elif serializer_class.data['role_name'] == "USER1":
                role = serializer_class.data['r_id']
                models.RolePermission.objects.add(r_id=role, p_id=show)
                models.RolePermission.objects.add(r_id=role, p_id=add)
                models.RolePermission.objects.add(r_id=role, p_id=change)
            elif serializer_class.data['role_name'] == "USER2":
                role = serializer_class.data['r_id']
                models.RolePermission.objects.add(r_id=role, p_id=show)
            return Response({'data': show})


class Signup(CreateAPIView):
    """This Api is used for Signup """
    serializer_class = serializers.SignupSerializerCustom

    def post(self, request, *args, **kwargs):
        try:
            user_details = models.User.objects.filter(email=request.data['email'])
            if user_details:
                return Response('You are already a user')
            else:
                password = hashers.make_password(request.data['password'])
                value = models.User.objects.create(user_name=request.data['user_name'], password=password,
                                                   email=request.data['email'])
                serializer = serializers.SignupSerializerCustom(data=request.data)
                if serializer.is_valid():
                    if serializer.data['role'] == 'ADMIN':
                        role = models.Roles.objects.get(role_name=serializer.data['role']).r_id
                        user_id = value.user_id
                        user_role = models.UserRole.objects.add(role, user_id)
                    elif serializer.data['role'] == 'USER1':
                        role = models.Roles.objects.get(role_name=serializer.data['role']).r_id
                        user_id = value.user_id
                        user_role = models.UserRole.objects.add(role, user_id)
                    elif serializer.data['role'] == 'USER2':
                        role = models.Roles.objects.get(role_name=serializer.data['role']).r_id
                        user_id = value.user_id
                        user_role = models.UserRole.objects.add(role, user_id)
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "signed in succesfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data})
        except Exception as error:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "cant register",
                             'status_flag': False,
                             'status': "Failed",
                             'error_details': str(error),
                             'data': []})


class Login(CreateAPIView):
    """This Api is used for Token creation and Login """
    serializer_class = serializers.LoginSerializer

    def post(self, request, *args, **kwargs):
        try:
            mail = models.User.objects.get(email=request.data['email'])
            password_matches = check_password(request.data['password'], mail.password)
            if password_matches:
                data = models.User.objects.filter(email=request.data['email'])
                serializer = serializers.SignupSerializer(data, many=True)
                token = generate_custom_model_token(mail.user_id)

                data_response = {
                    'response_code': status.HTTP_200_OK,
                    'message': "logged in succesfully",
                    'status_flag':True,
                    'status': "success",
                    'error_details': None,
                    'data':{'user':serializer.data,'Token':token},
                    }
                return Response(data_response)
            else:
                data_response = {
                    'response_code': status.HTTP_400_BAD_REQUEST,
                    'message': "email not registered",
                    'status_flag': False,
                    'status': "success",
                    'error_details': None,
                    'data': []}
                return Response(data_response)
        except Exception as error:
            return Response({
                'response_code':status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message':'INTERNAL_SERVER_ERROR',
                'status_flag': False,
                'status': "success",
                'error_details': str(error),
                'data': []})


class CreateProduct(CreateAPIView):
    """This Api is used to Create Products """
    serializer_class = serializers.ProductSerializer
    permission_classes = [TokenPermission]

    def post(self, request, *args, **kwargs):
        try:
            serializer_class = serializers.ProductSerializer(data=request.data)
            if serializer_class.is_valid(raise_exception=True):
                value = serializer_class.save()
                data_response = {
                    'response_code': status.HTTP_200_OK,
                    'message': "Product Created succesfully",
                    'status_flag': True,
                    'status': "success",
                    'method':request.method,
                    'error_details': None,
                    'data': {'user': serializer_class.data}}
                return Response(data_response)
            else:
                data_response = {
                    'response_code': status.HTTP_400_BAD_REQUEST,
                    'message': "email not registered",
                    'status_flag': False,
                    'status': "Failed",
                    'error_details': None,
                    'data': []}
                return Response(data_response)
        except Exception as error:
            return Response({
                'response_code':status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message':'INTERNAL_SERVER_ERROR',
                'status_flag': False,
                'status': "Failed",
                'error_details': str(error),
                'data': []})


class ProductDetails(RetrieveAPIView):
    """This Api is used to Get Product Details with Authentication """
    queryset = models.Product.objects.all()
    permission_classes = [TokenPermission]

    def get(self, request, *args, **kwargs):
        queryset = models.Product.objects.all()
        serializer_class = serializers.ProductSerializer(queryset, many=True)
        response = {
                    "status": status.HTTP_200_OK,
                    "message": "success",
                    "data": serializer_class.data,
                    "request":request.method,
                }
        return Response(response, status=status.HTTP_200_OK)


class DeleteProduct(DestroyAPIView):
    """This Api is used to Delete Products """

    serializer_class = serializers.DeleteProductSerializer
    permission_classes = [TokenPermission]
    queryset = models.Product.objects.all()

    @swagger_auto_schema(request_body=serializer_class)
    def delete(self, request, *args, **kwargs):
        query = models.Product.objects.filter(id=request.data['id'])
        query.delete()
        response = {
            "status": status.HTTP_200_OK,
            "message": "successfully deleted",
        }
        return Response(response, status=status.HTTP_200_OK)


class ChangeProduct(UpdateAPIView):
    """This Api is used to Change Products """

    serializer_class = serializers.UpdateSerializer
    permission_classes = [TokenPermission]
    queryset = models.Product.objects.all()

    def put(self, request, *args, **kwargs):
        changes = models.Product.objects.get(id=request.data['id'])
        serializer_class = serializers.ProductSerializer(instance=changes, data=request.data)
        if serializer_class.is_valid():
            serializer_class.save()
            data = {
                'response': 'success',
                'data': [serializer_class.data]
            }
            return Response(data)
        return Response(serializer_class.errors)
from django.urls import path
from projectx_app.views import *
urlpatterns = [
    path('PermissionGenerator/',PermissionGenerator.as_view()),
    path('Rolecreation/',AddRole.as_view()),
    path('Signup/',Signup.as_view()),
    path('Login/',Login.as_view()),
    path('CreateProduct',CreateProduct.as_view()),
    path('ProductDetails',ProductDetails.as_view()),
    path('ProductChange',ChangeProduct.as_view()),
    path('ProductDelete',DeleteProduct.as_view()),
]
from django.urls import path
from projectx_app.views import *
urlpatterns = [
    path('contenttype/',ContentType.as_view()),
    path('rolecreation/',AddRole.as_view()),
]
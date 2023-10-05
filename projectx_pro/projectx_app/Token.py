from django.db import models
from rest_framework import status
import secrets
from .models import User  # Import your custom model
from datetime import datetime


class Token(models.Model):
    key = models.CharField(unique=True, max_length=40, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    user = models.ForeignKey('User', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'Token'

    def generate_custom_model_token(custom_model_id):
        try:
            custom_model_instance = User.objects.get(user_id=custom_model_id)
            token = secrets.token_hex(20)
            Token.objects.create(user=custom_model_instance, key=token, created_at=datetime.now())
            return token
        except User.DoesNotExist:
            return None, {'error': 'Custom model not found'}, status.HTTP_404_NOT_FOUND
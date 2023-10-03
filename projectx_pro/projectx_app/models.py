from django.db import models
from . import permission


class RoleManager(models.Manager):
    pass


class RolePermissionManager(models.Manager):
    def add(self,rid,perm):
        user = self.model(role = rid,permission=perm)
        user.save(using=self._db)


class RolePermission(models.Model):
    id = models.BigAutoField(primary_key=True)
    role = models.ForeignKey('Roles', models.DO_NOTHING)
    permission = models.ForeignKey(permission.Permission, models.DO_NOTHING, db_column='permission')
    objects = RolePermissionManager
    class Meta:
        managed = False
        db_table = 'role_permission'


class Roles(models.Model):
    r_id = models.BigAutoField(primary_key=True)
    role_name = models.CharField(max_length=100, blank=True, null=True)
    objects = RoleManager

    class Meta:
        managed = False
        db_table = 'roles'


class UserManager(models.Manager):
    def create(self,username,password,email):
        user = self.model(username=username,password=password,email=email)
        user.save(using=self._db)


class User(models.Model):
    user_id = models.BigAutoField(primary_key=True)
    user_name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'user'


class UserRole(models.Model):
    id = models.BigAutoField(primary_key=True)
    role = models.ForeignKey(Roles, models.DO_NOTHING)
    user = models.ForeignKey(User, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'user_role'


class ContentType(models.Model):
    id = models.BigAutoField(primary_key=True)
    model_name = models.CharField(max_length=100, blank=True, null=True)
    is_permission_provided = models.IntegerField(blank=True, null=True, default=0)

    class Meta:
        managed = False
        db_table = 'content_type'



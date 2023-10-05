from django.db import models
from projectx_app import permission
from .permission import Permission


class RoleManager(models.Manager):
    pass


class RolePermissionManager(models.Manager):
    def add(self,r_id,p_id):
        user = self.model(r_id=r_id,p_id=p_id)
        user.save(using=self._db)


class RolePermission(models.Model):
    id = models.BigAutoField(primary_key=True)
    r = models.ForeignKey('Roles', models.DO_NOTHING)
    p = models.ForeignKey('Permission', models.DO_NOTHING)
    objects = RolePermissionManager()

    class Meta:
        managed = False
        db_table = 'role_permission'


class Roles(models.Model):
    r_id = models.BigAutoField(primary_key=True)
    role_name = models.CharField(unique=True, max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'roles'


class UserManager(models.Manager):
    def create(self,user_name,password,email):
        user = self.model(user_name=user_name,password=password,email=email)
        user.save(using=self._db)


class User(models.Model):
    user_id = models.BigAutoField(primary_key=True)
    user_name = models.CharField(max_length=100)
    email = models.CharField(unique=True, max_length=100)
    password = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'user'



class UserRoleManager(models.Manager):
    def add(self,r_id,u_id):
        user = self.model(r_id=r_id,user_id=u_id)
        user.save(using=self._db)


class UserRole(models.Model):
    id = models.BigAutoField(primary_key=True)
    r = models.ForeignKey('Roles', models.DO_NOTHING)
    user = models.ForeignKey('User', models.DO_NOTHING)
    objects = UserRoleManager()

    class Meta:
        managed = False
        db_table = 'user_role'


class PermissionGenerator(models.Model):
    id = models.BigAutoField(primary_key=True)
    model_name = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'permission_generator'


class Product(models.Model):
    id = models.BigAutoField(primary_key=True)
    product_name = models.CharField(max_length=100)
    price = models.BigIntegerField()
    description = models.CharField(max_length=100, blank=True, null=True)
    pcount = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'product'
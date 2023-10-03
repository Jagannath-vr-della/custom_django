from django.db import models


class PermissionManager(models.Manager):
    def create(self,app_name,model_name,content_name,p_id,p_name):
        perm = self.model(app_name=app_name,model_name=model_name,content_name=content_name,p_id=p_id,p_name=p_name)
        perm.save(using=self._db)


class Permission(models.Model):
    p_id = models.BigAutoField(primary_key=True)
    p_name = models.CharField(max_length=100, blank=True, null=True)
    content_name = models.CharField(max_length=100, blank=True, null=True)
    model_name = models.CharField(db_column='model-name', max_length=100, blank=True, null=True)  # Field renamed to remove unsuitable characters.
    app_name = models.CharField(max_length=100)
    objects = PermissionManager

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.app_name = self.app_name
            self.model_name = self.model_name
            self.content_name = self.content_name
            self.p_name = self.p_name
            self.p_id = self.p_id
            super().save(*args, **kwargs)

    class Meta:
        managed = False
        db_table = 'permission'
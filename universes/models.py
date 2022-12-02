from django.db import models

# Create your models here.
class Universe(models.Model):
    name = models.CharField(max_length=15, verbose_name="İsim")
    slogan = models.CharField(max_length=50, blank=True, null=True, verbose_name="Slogan")
    detail = models.TextField(max_length=200, verbose_name="Detay")
    cover = models.ImageField(upload_to='universe',blank=True,null=True, verbose_name="Fotoğraf")
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name
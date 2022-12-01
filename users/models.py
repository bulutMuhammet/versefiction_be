from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models





class Profile(models.Model):

    GENDER       = (('e', 'Erkek'), ('k', 'Kadın'), ('d', 'Diğer'))

    user         = models.OneToOneField(User, related_name="profile", verbose_name="Kullanıcı", on_delete=models.CASCADE)
    photo        = models.FileField(upload_to='user_photos',blank=False,null=False, verbose_name="Fotoğraf")
    gender       = models.CharField(choices=GENDER,blank=True, null=True, max_length=15, verbose_name='Cinsiyet')
    birth_date   = models.DateField(blank=True, null=True, verbose_name="Doğum Tarihi")
    bio          = models.TextField(blank=True, null=True, verbose_name="Hakkımda")
    is_verified = models.BooleanField(blank=True, null=True, default=False, verbose_name="Onaylanmış mı?")
    created_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = "Profil"
        verbose_name_plural = "Profiller"









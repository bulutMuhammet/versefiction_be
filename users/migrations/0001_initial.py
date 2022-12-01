# Generated by Django 4.1.3 on 2022-12-01 19:46

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('photo', models.FileField(upload_to='user_photos', verbose_name='Fotoğraf')),
                ('gender', models.CharField(blank=True, choices=[('e', 'Erkek'), ('k', 'Kadın'), ('d', 'Diğer')], max_length=15, null=True, verbose_name='Cinsiyet')),
                ('birth_date', models.DateField(blank=True, null=True, verbose_name='Doğum Tarihi')),
                ('bio', models.TextField(blank=True, null=True, verbose_name='Hakkımda')),
                ('is_verified', models.BooleanField(blank=True, default=False, null=True, verbose_name='Onaylanmış mı?')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL, verbose_name='Kullanıcı')),
            ],
            options={
                'verbose_name': 'Profil',
                'verbose_name_plural': 'Profiller',
            },
        ),
    ]

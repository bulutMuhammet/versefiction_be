# Generated by Django 4.1.3 on 2022-12-02 03:28

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('universes', '0002_alter_universe_cover_alter_universe_slogan'),
        ('stories', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='story',
            name='universe',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='stories', to='universes.universe'),
            preserve_default=False,
        ),
    ]

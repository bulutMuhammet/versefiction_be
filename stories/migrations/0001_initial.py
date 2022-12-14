# Generated by Django 4.1.3 on 2022-12-02 03:25

from django.db import migrations, models
import multiselectfield.db.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Story',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=15, verbose_name='İsim')),
                ('slogan', models.CharField(blank=True, max_length=50, null=True, verbose_name='Slogan')),
                ('detail', models.TextField(max_length=200, verbose_name='Detay')),
                ('category', multiselectfield.db.fields.MultiSelectField(choices=[('sci_fi', 'Science Fiction'), ('super_hero', 'Superhero'), ('fairy_tale', 'Fairy Tale'), ('humour', 'Humour')], max_length=20)),
                ('cover', models.ImageField(blank=True, null=True, upload_to='story', verbose_name='Fotoğraf')),
                ('age_range', models.CharField(blank=True, choices=[('sci_fi', 'Science Fiction'), ('super_hero', 'Superhero'), ('fairy_tale', 'Fairy Tale'), ('humour', 'Humour')], max_length=30, null=True, verbose_name='Yaş Aralığı')),
                ('adult_content', models.BooleanField(default=False)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
                ('is_deleted', models.BooleanField(default=False)),
            ],
        ),
    ]

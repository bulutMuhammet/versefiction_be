from ckeditor.fields import RichTextField
from django.db import models

# Create your models here.
from multiselectfield import MultiSelectField


class Story(models.Model):
    CATEGORIES = (
        ('sci_fi', 'Science Fiction'),
        ('super_hero', 'Superhero'),
        ('fairy_tale', 'Fairy Tale'),
        ('humour', 'Humour'),
    )
    AGE_RANGE = (
        ('sci_fi', 'Science Fiction'),
        ('super_hero', 'Superhero'),
        ('fairy_tale', 'Fairy Tale'),
        ('humour', 'Humour'),
    )
    universe = models.ForeignKey(
        "universes.Universe", on_delete=models.CASCADE, related_name="stories")
    name = models.CharField(max_length=15, verbose_name="İsim")
    slogan = models.CharField(max_length=50, blank=True, null=True, verbose_name="Slogan")
    detail = models.TextField(max_length=200, verbose_name="Detay")
    category = MultiSelectField(choices=CATEGORIES, max_choices=3, max_length=500)
    cover = models.ImageField(upload_to='story',blank=True,null=True, verbose_name="Fotoğraf")
    age_range = models.CharField(choices=AGE_RANGE,blank=True, null=True, verbose_name='Yaş Aralığı', max_length=30)
    adult_content = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Chapter(models.Model):
    id = models.AutoField(primary_key=True)
    index = models.PositiveIntegerField(verbose_name="Sıralama", default=1)
    story = models.ForeignKey(
        "stories.Story", on_delete=models.CASCADE, related_name="chapters")
    title = models.CharField(max_length=50, verbose_name="Başlık")
    content = RichTextField()
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_draft = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.title

    class Meta:
        unique_together = (('index', 'story'),)

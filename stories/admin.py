from django.contrib import admin
from stories.models import Story, Chapter








@admin.register(Story)
class StoryAdmin(admin.ModelAdmin):
    list_display = ('universe','name', 'created_date', 'modified_date','is_deleted',)

    class Meta:
        model = Story

@admin.register(Chapter)
class ChapterAdmin(admin.ModelAdmin):
    list_display = ('index','story', 'title', 'modified_date','is_deleted',)

    class Meta:
        model = Chapter
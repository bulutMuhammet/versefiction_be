from django.contrib import admin
from universes.models import Universe








@admin.register(Universe)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_date', 'modified_date','is_deleted',)

    class Meta:
        model = Universe

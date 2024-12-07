from django.contrib import admin
from .models import Profile, Libro, Prestamo

admin.site.register(Profile)
admin.site.register(Libro)
admin.site.register(Prestamo)


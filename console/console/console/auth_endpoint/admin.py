from django.contrib import admin
from . import models
# Register your models here.
admin.site.register(models.EmailChangeRequest)
admin.site.register(models.PasswordChangeRequest)
admin.site.register(models.ForgotPasswordRequest)
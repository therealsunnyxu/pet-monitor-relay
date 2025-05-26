from django.db import models
from django.conf import settings
from datetime import timedelta, datetime
import uuid
# Create your models here.

class AbstractResetRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code = models.IntegerField(null=False)
    email_sent_at = models.DateTimeField(auto_now_add=True, null=False)
    expires_at = models.DurationField(null=False, default=timedelta(minutes=15))
    request_fulfilled_at = models.DateTimeField(null=True)

    class Meta:
        abstract = True

    def is_expired(self):
        return self.email_sent_at + self.expires_at <= datetime.now()
    
    def is_fulfilled(self):
        return self.request_fulfilled_at is not None # or self.request_fulfilled_at > datetime.now()


class EmailChangeRequest(AbstractResetRequest):
    new_email = models.EmailField(null=False)
    
class PasswordChangeRequest(AbstractResetRequest):
    new_password = models.TextField(null=False)

class ForgotPasswordRequest(AbstractResetRequest):
    uuid = models.UUIDField(primary_key=True, null=False, default=uuid.uuid4(), editable=False)

class ForgotPasswordChangeRequest(models.Model):
    original_request = models.ForeignKey(ForgotPasswordRequest, on_delete=models.CASCADE)
    request_fulfilled_at = models.DateTimeField(null=True)
    expires_at = models.DateTimeField(null=False, default=lambda _:datetime.now() + timedelta(days=1))
    request_cancelled = models.BooleanField(null=False, default=False)

    def is_expired(self):
        return self.expires_at <= datetime.now()
    
    def is_fulfilled(self):
        return self.request_fulfilled_at is not None # or self.request_fulfilled_at > datetime.now()
    
    def is_cancelled(self):
        return self.request_cancelled == True
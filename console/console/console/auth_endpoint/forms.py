from django import forms

class CancellableForm(forms.Form):
    cancelled = forms.NullBooleanField(label="Cancel Request")

class LoginForm(forms.Form):
    username = forms.CharField(label="Username", max_length=150)
    password = forms.CharField(
        widget=forms.PasswordInput(), label="Password", max_length=128
    )
    remember_me = forms.BooleanField(label="Remember Me", required=False)

class EmailChangeRequestForm(forms.Form):
    old_email = forms.EmailField(label="Old Email")
    new_email = forms.EmailField(label="New Email")
    password = forms.CharField(
        widget=forms.PasswordInput(), label="Password", max_length=128
    )

class PasswordChangeRequestForm(forms.Form):
    old_password = forms.CharField(
        widget=forms.PasswordInput(), label="Old Password", max_length=128
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(), label="New Password", max_length=128
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(), label="Confirm New Password", max_length=128
    )

class VerificationCodeForm(forms.Form):
    code = forms.IntegerField(label="Code")

class ForgotPasswordRequestForm(forms.Form):
    email = forms.EmailField(label="Email")

class ForgotPasswordChangeForm(CancellableForm):
    new_password = forms.CharField(
        widget=forms.PasswordInput(), label="New Password", max_length=128
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(), label="Confirm New Password", max_length=128
    )
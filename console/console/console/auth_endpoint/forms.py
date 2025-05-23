from django import forms


class LoginForm(forms.Form):
    username = forms.CharField(label="Username", max_length=150)
    password = forms.CharField(
        widget=forms.PasswordInput(), label="Password", max_length=128
    )
    remember_me = forms.BooleanField(label="Remember Me", required=False)

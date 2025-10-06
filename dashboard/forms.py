from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import user

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = user
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add Bootstrap classes and placeholders for better styling
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
            if field_name == 'username':
                field.widget.attrs['placeholder'] = 'Enter your username'
            elif field_name == 'email':
                field.widget.attrs['placeholder'] = 'Enter your email'
            elif field_name == 'password1':
                field.widget.attrs['placeholder'] = 'Enter your password'
            elif field_name == 'password2':
                field.widget.attrs['placeholder'] = 'Enter your password again'

class WalletCreationForm(forms.Form):
    testnet_username = forms.CharField(label='Testnet Username', max_length=150)
    testnet_password = forms.CharField(label='Testnet Password', widget=forms.PasswordInput)
    user_id = forms.IntegerField(label='User ID')
    currency = forms.CharField(max_length=10, label='Currency')
    type = forms.ChoiceField(choices=[('spot', 'Spot'), ('margin', 'Margin'), ('credit', 'Credit'), ('debit', 'Debit')], label='Type')
    balance = forms.DecimalField(label='Balance')
    balance_blocked = forms.DecimalField(label='Balance Blocked')
    is_active = forms.BooleanField(label='Is Active', required=False, initial=True)
    recovery_state = forms.IntegerField(label='Recovery State')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field_name != 'is_active':
                field.widget.attrs['class'] = 'form-control'
            
            if field_name == 'testnet_username':
                field.widget.attrs['placeholder'] = 'Enter your testnet admin username'
            elif field_name == 'testnet_password':
                field.widget.attrs['placeholder'] = 'Enter your testnet admin password'
            elif field_name == 'user_id':
                field.widget.attrs['placeholder'] = 'Enter the user ID'
            elif field_name == 'currency':
                field.widget.attrs['placeholder'] = 'Enter the currency (e.g., BTC)'
            elif field_name == 'balance':
                field.widget.attrs['placeholder'] = 'Enter the balance'
            elif field_name == 'balance_blocked':
                field.widget.attrs['placeholder'] = 'Enter the blocked balance'
            elif field_name == 'recovery_state':
                field.widget.attrs['placeholder'] = 'Enter the recovery state'

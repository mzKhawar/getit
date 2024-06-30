
from django import forms
from .models import CardioLogModel

class CardioLogForm(forms.ModelForm):
    class Meta:
        model = CardioLogModel
        fields = '__all__'





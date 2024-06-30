from django import forms
from .models import WeightLogModel

class WeightLogForm(forms.ModelForm):
    class Meta:
        model = WeightLogModel
        fields = '__all__'
        label = {
                'weight': 'Current Weight'
                }




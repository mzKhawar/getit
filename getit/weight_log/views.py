from django.shortcuts import render
from .models import WeightLogModel
from .forms import WeightLogForm

# Create your views here.

def index(request):
    form = WeightLogForm(request.POST or None)
    
    if form.is_valid():
        form.save()
    
    context = {'form': form}

    return render(request, "weight_log/index.html", context)


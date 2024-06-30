from django.shortcuts import render
from .forms import CardioLogForm
from django.http import HttpResponse
# Create your views here.

def index(request):
    form = CardioLogForm(request.POST or None)
    if form.is_valid():
        form.save()
    context = {'form': form}
    return render(request, "workout_log/index.html", context)


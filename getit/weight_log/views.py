from django.shortcuts import render, redirect, reverse
from .models import WeightLogModel
from .forms import WeightLogForm
from django.http import HttpResponseRedirect, HttpResponse

# Create your views here.

def index(request):
    form = WeightLogForm(request.POST or None)
    weight_logs = WeightLogModel.objects.all()

    if form.is_valid():
        form.save()
    
    context = {'form': form, 
               'weight_logs': weight_logs,
               }

    if request.method == "POST":
        return redirect(reverse('index'))
    else:
        return render(request, "weight_log/index.html", context)


def delete_all_records(request):
    WeightLogModel.objects.all().delete()
    return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))


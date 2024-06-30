from django.urls import path
from . import views

urlpatterns = [
        path("", views.index, name="index"),     
        path("delete-all/", views.delete_all_records, name="delete_all_records"), 
        ]

from django.db import models

# Create your models here.

class WeightLogModel(models.Model):
    date_time = models.DateTimeField(auto_now=True)
    weight = models.DecimalField(max_digits=5, decimal_places=2)

    def __str__(self):
        return f"Weight on {date_time}: {weight}"

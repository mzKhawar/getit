from django.db import models

# Create your models here.

class CardioTypeModel(models.Model):
    cardio_type = models.CharField(max_length=200)

    def __str__(self):
        return self.cardio_type

class CardioLogModel(models.Model):
    cardio_type = models.ForeignKey(CardioTypeModel, on_delete=models.CASCADE)
    duration = models.DurationField()
    date_time = models.DateTimeField()


class LiftTypeModel(models.Model):
    lift_type = models.CharField(max_length=200)

    def __str__(self):
        return self.lift_type


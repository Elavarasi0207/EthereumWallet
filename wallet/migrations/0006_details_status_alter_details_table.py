# Generated by Django 4.1.1 on 2022-10-22 07:45

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0005_details_public_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='details',
            name='status',
            field=models.CharField(default=django.utils.timezone.now, max_length=500),
            preserve_default=False,
        ),
        migrations.AlterModelTable(
            name='details',
            table='wallet_details',
        ),
    ]

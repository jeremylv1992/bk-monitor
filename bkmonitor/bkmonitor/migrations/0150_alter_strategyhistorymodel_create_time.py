# Generated by Django 3.2.15 on 2023-12-25 03:31

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('bkmonitor', '0149_monitormigration'),
    ]

    operations = [
        migrations.AlterField(
            model_name='strategyhistorymodel',
            name='create_time',
            field=models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='创建时间'),
        ),
    ]
# Generated by Django 5.1.6 on 2025-05-09 03:53

import datetime
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auth_endpoint", "0006_alter_forgotpasswordchangerequest_expires_at_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="forgotpasswordchangerequest",
            name="expires_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2025, 5, 10, 3, 53, 19, 311394, tzinfo=datetime.timezone.utc
                )
            ),
        ),
        migrations.AlterField(
            model_name="forgotpasswordrequest",
            name="uuid",
            field=models.UUIDField(
                default=uuid.UUID("8a2a2442-bc9b-4a8a-a644-35ce989fbcee"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
    ]

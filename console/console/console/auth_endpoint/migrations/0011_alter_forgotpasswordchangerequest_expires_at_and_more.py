# Generated by Django 5.1.6 on 2025-05-09 04:03

import datetime
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auth_endpoint", "0010_alter_forgotpasswordchangerequest_expires_at_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="forgotpasswordchangerequest",
            name="expires_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2025, 5, 10, 4, 3, 24, 773223, tzinfo=datetime.timezone.utc
                )
            ),
        ),
        migrations.AlterField(
            model_name="forgotpasswordrequest",
            name="uuid",
            field=models.UUIDField(
                default=uuid.UUID("20eb6263-fb09-4e4d-830f-984a386ba86a"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
    ]

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
        ('library', '0006_search_filter_seo'),
    ]

    operations = [
        migrations.CreateModel(
            name='SecurityEventLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(max_length=80)),
                ('severity', models.CharField(default='info', max_length=20)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='accounts.user')),
            ],
        ),
        migrations.CreateModel(
            name='SystemErrorLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source', models.CharField(max_length=80)),
                ('message', models.TextField()),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='BackupRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('backup_type', models.CharField(max_length=30)),
                ('status', models.CharField(default='queued', max_length=30)),
                ('location', models.CharField(blank=True, max_length=500)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('triggered_by', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='accounts.user')),
            ],
        ),
        migrations.CreateModel(
            name='SystemSetting',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('maintenance_mode', models.BooleanField(default=False)),
                ('disable_downloads', models.BooleanField(default=False)),
                ('disable_code_entry', models.BooleanField(default=False)),
                ('notification_message', models.CharField(blank=True, max_length=255)),
                ('rate_limit_config', models.JSONField(blank=True, default=dict)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]

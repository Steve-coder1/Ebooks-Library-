from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
        ('library', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='FailedCodeAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code_value', models.CharField(blank=True, max_length=64)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('session_key', models.CharField(blank=True, max_length=64)),
                ('reason', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='AccessCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code_value', models.CharField(db_index=True, max_length=64, unique=True)),
                ('is_used', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('expires_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by_admin', models.ForeignKey(null=True, on_delete=models.deletion.SET_NULL, related_name='created_codes', to='accounts.user')),
                ('ebook', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='access_codes', to='library.ebook')),
            ],
        ),
        migrations.CreateModel(
            name='CodeUsageLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('device_info', models.CharField(blank=True, max_length=255)),
                ('used_at', models.DateTimeField(auto_now_add=True)),
                ('download_completed', models.BooleanField(default=False)),
                ('code', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='usage_logs', to='library.accesscode')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='accounts.user')),
            ],
        ),
    ]

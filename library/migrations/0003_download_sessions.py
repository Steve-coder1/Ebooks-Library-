from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
        ('library', '0002_codes_and_logs'),
    ]

    operations = [
        migrations.CreateModel(
            name='DownloadSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('expires_at', models.DateTimeField()),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('code', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='download_sessions', to='library.accesscode')),
                ('ebook', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='download_sessions', to='library.ebook')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='accounts.user')),
            ],
        ),
        migrations.CreateModel(
            name='FileDownloadAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('attempted_at', models.DateTimeField(auto_now_add=True)),
                ('success', models.BooleanField(default=False)),
                ('download_completed', models.BooleanField(default=False)),
                ('error_reason', models.CharField(blank=True, max_length=255)),
                ('ebook_file', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='download_attempts', to='library.ebookfile')),
                ('session', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='file_attempts', to='library.downloadsession')),
            ],
        ),
    ]

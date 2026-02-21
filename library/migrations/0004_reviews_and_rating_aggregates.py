from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
        ('library', '0003_download_sessions'),
    ]

    operations = [
        migrations.AddField(
            model_name='ebook',
            name='average_rating',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=3),
        ),
        migrations.AddField(
            model_name='ebook',
            name='review_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.CreateModel(
            name='Review',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rating', models.PositiveSmallIntegerField()),
                ('review_text', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('ebook', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='reviews', to='library.ebook')),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='reviews', to='accounts.user')),
            ],
            options={'unique_together': {('ebook', 'user')}},
        ),
        migrations.CreateModel(
            name='ReviewAbuseLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('reason', models.CharField(max_length=128)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ebook', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='library.ebook')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='accounts.user')),
            ],
        ),
    ]

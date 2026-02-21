from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
        ('library', '0004_reviews_and_rating_aggregates'),
    ]

    operations = [
        migrations.CreateModel(
            name='DownloadHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('downloaded_at', models.DateTimeField(auto_now_add=True)),
                ('version_label', models.CharField(max_length=100)),
                ('code', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='download_history', to='library.accesscode')),
                ('ebook', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='download_history', to='library.ebook')),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='download_history', to='accounts.user')),
            ],
        ),
    ]

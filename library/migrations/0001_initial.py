from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120, unique=True)),
                ('slug', models.SlugField(max_length=140, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Ebook',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('author', models.CharField(max_length=255)),
                ('cover_image_path', models.CharField(blank=True, max_length=400)),
                ('summary_text', models.TextField(blank=True)),
                ('sample_preview_path', models.CharField(blank=True, max_length=400)),
                ('is_featured', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('download_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('category', models.ForeignKey(on_delete=models.deletion.PROTECT, related_name='ebooks', to='library.category')),
            ],
        ),
        migrations.CreateModel(
            name='EbookFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_name', models.CharField(max_length=255)),
                ('file_path', models.CharField(max_length=500)),
                ('file_size', models.BigIntegerField()),
                ('version_label', models.CharField(default='v1.0', max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ebook', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='files', to='library.ebook')),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='EbookDownload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ebook_file', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='downloads', to='library.ebookfile')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, to='accounts.user')),
            ],
        ),
        migrations.CreateModel(
            name='Favorite',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ebook', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='favorited_by', to='library.ebook')),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='favorites', to='accounts.user')),
            ],
            options={'unique_together': {('user', 'ebook')}},
        ),
    ]

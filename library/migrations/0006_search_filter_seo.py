from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('library', '0005_personalization_history'),
    ]

    operations = [
        migrations.AddField(
            model_name='ebook',
            name='slug',
            field=models.SlugField(blank=True, max_length=255, unique=True),
        ),
        migrations.AddField(
            model_name='ebook',
            name='keywords',
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.AddField(
            model_name='ebook',
            name='meta_title',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='ebook',
            name='meta_description',
            field=models.CharField(blank=True, max_length=320),
        ),
        migrations.CreateModel(
            name='SearchQueryLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('term', models.CharField(db_index=True, max_length=255)),
                ('result_count', models.PositiveIntegerField(default=0)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=80, unique=True)),
                ('slug', models.SlugField(max_length=90, unique=True)),
            ],
        ),
        migrations.AddField(
            model_name='ebook',
            name='tags',
            field=models.ManyToManyField(blank=True, related_name='ebooks', to='library.tag'),
        ),
    ]

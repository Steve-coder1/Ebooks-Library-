from django.contrib.sitemaps import Sitemap
from django.urls import reverse

from .models import Category, Ebook


class StaticViewSitemap(Sitemap):
    priority = 0.5
    changefreq = 'weekly'

    def items(self):
        return ['library:catalog', 'library:categories', '/about/', '/contact/', '/privacy/', '/terms/']

    def location(self, item):
        if item.startswith('/'):
            return item
        return reverse(item)


class CategorySitemap(Sitemap):
    priority = 0.7
    changefreq = 'daily'

    def items(self):
        return Category.objects.all()

    def location(self, obj):
        return f"/ebooks/catalog/?category={obj.slug}"


class EbookSitemap(Sitemap):
    priority = 0.8
    changefreq = 'daily'

    def items(self):
        return Ebook.objects.filter(is_active=True)

    def location(self, obj):
        return reverse('library:ebook_detail', kwargs={'slug': obj.slug})

    def lastmod(self, obj):
        return obj.updated_at

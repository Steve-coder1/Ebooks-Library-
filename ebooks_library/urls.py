from django.contrib import admin
from django.contrib.sitemaps.views import sitemap
from django.urls import include, path

from library import views as library_views
from library.sitemaps import CategorySitemap, EbookSitemap, StaticViewSitemap

sitemaps = {
    'static': StaticViewSitemap,
    'categories': CategorySitemap,
    'ebooks': EbookSitemap,
}

urlpatterns = [
    path('', library_views.homepage, name='home'),
    path('django-admin/', admin.site.urls),
    path('auth/', include('accounts.urls')),
    path('ebooks/', include('library.urls')),
    path('sitemap.xml', sitemap, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.sitemap'),
    path('<slug:page_slug>/', library_views.static_page, name='static_page'),
]

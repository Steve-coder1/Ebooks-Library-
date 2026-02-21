from django.urls import path

from . import views

app_name = 'library'

urlpatterns = [
    path('list/', views.catalog_listing, name='catalog_listing'),
    path('catalog/', views.ebook_catalog, name='catalog'),
    path('search/suggestions/', views.search_suggestions, name='search_suggestions'),
    path('search/analytics/', views.search_analytics, name='search_analytics'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/maintenance/', views.admin_toggle_maintenance, name='admin_toggle_maintenance'),
    path('admin/backups/trigger/', views.admin_trigger_backup, name='admin_trigger_backup'),
    path('admin/cleanup/run/', views.admin_run_cleanup, name='admin_run_cleanup'),
    path('admin/exports/', views.admin_exports, name='admin_exports'),
    path('categories/', views.categories, name='categories'),
    path('history/', views.download_history, name='download_history'),
    path('admin/history/', views.admin_download_history, name='admin_download_history'),
    path('<int:ebook_id>/preview/', views.ebook_preview, name='preview'),
    path('<int:ebook_id>/favorite/', views.toggle_favorite, name='favorite'),
    path('favorites/', views.list_favorites, name='list_favorites'),
    path('<int:ebook_id>/reviews/', views.ebook_reviews, name='ebook_reviews'),
    path('<int:ebook_id>/reviews/upsert/', views.upsert_review, name='upsert_review'),
    path('reviews/me/', views.my_reviews, name='my_reviews'),
    path('reviews/me/<int:review_id>/delete/', views.delete_my_review, name='delete_my_review'),
    path('reviews/<int:review_id>/delete/', views.admin_delete_review, name='admin_delete_review'),
    path('admin/review-analytics/', views.review_analytics, name='review_analytics'),
    path('files/<int:file_id>/download-link/', views.create_download_link, name='create_download_link'),
    path('download/<str:token>/', views.secure_download, name='secure_download'),
    path('code-entry/', views.code_entry_interface, name='code_entry'),
    path('codes/validate/', views.validate_code, name='validate_code'),
    path('codes/<str:token>/download/<int:file_id>/', views.code_download, name='code_download'),
    path('codes/files/<str:file_token>/download/', views.code_file_download, name='code_file_download'),
    path('codes/<str:token>/bundle.zip', views.code_download_bundle_zip, name='code_download_bundle_zip'),
    path('<int:ebook_id>/codes/generate/', views.generate_code, name='generate_code'),
    path('codes/<int:code_id>/deactivate/', views.deactivate_code, name='deactivate_code'),
    path('<slug:slug>/', views.ebook_detail_by_slug, name='ebook_detail'),
]

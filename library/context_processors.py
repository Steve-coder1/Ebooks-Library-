from .models import Category, Ebook, SystemSetting


def site_notifications(request):
    system_banner = None
    promo_banners = []

    try:
        cfg = SystemSetting.objects.first()
        if cfg and cfg.notification_message:
            system_banner = {
                'id': 'system-notification',
                'message': cfg.notification_message,
                'level': 'warning' if cfg.maintenance_mode else 'info',
            }

        featured = Ebook.objects.filter(is_active=True, is_featured=True).order_by('-updated_at')[:3]
        promo_banners.extend(
            {
                'id': f'promo-ebook-{ebook.id}',
                'title': f'Featured: {ebook.title}',
                'message': (ebook.summary_text or ebook.description or 'Explore this featured ebook.')[:140],
                'link': f'/ebooks/{ebook.slug}/',
                'link_label': 'View ebook',
            }
            for ebook in featured
        )

        if len(promo_banners) < 3:
            newest_categories = Category.objects.order_by('-created_at')[: 3 - len(promo_banners)]
            promo_banners.extend(
                {
                    'id': f'promo-category-{cat.id}',
                    'title': f'New category: {cat.name}',
                    'message': f'Browse fresh additions in {cat.name}.',
                    'link': f'/ebooks/list/?category={cat.slug}',
                    'link_label': 'Explore category',
                }
                for cat in newest_categories
            )
    except Exception:
        return {'system_banner': None, 'promo_banners': []}

    return {'system_banner': system_banner, 'promo_banners': promo_banners}

from decimal import Decimal

from django.db import migrations

# Anchored on the 10-credit pack at $8.45 ($0.845/credit); the unit price falls
# roughly 6 percentage points per tier so bigger top-ups are visibly cheaper.
PACKS = [
    # (credits, price_usd, sort_order)
    (10, "8.45", 1),
    (30, "23.90", 2),
    (75, "55.90", 3),
    (200, "138.00", 4),
    (500, "322.00", 5),
]


def seed_packs(apps, schema_editor):
    CreditPack = apps.get_model("billing", "CreditPack")
    for credits, price, sort_order in PACKS:
        CreditPack.objects.update_or_create(
            credits=credits,
            defaults={
                "price_usd": Decimal(price),
                "sort_order": sort_order,
                "is_active": True,
            },
        )


def unseed_packs(apps, schema_editor):
    CreditPack = apps.get_model("billing", "CreditPack")
    CreditPack.objects.filter(credits__in=[credits for credits, _, _ in PACKS]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_packs, unseed_packs),
    ]

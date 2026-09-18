# ============================================================
# Mini SIEM - Correlation Engine Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine


def main():

    # SQLite veritabanına bağlanıyoruz.
    database = DatabaseManager()

    # Correlation Engine oluşturuyoruz.
    engine = CorrelationEngine()

    # Veritabanındaki eventleri alıyoruz.
    rows = database.get_all_events()

    # Tuple kayıtlarını dictionary formatına çeviriyoruz.
    events = engine.database_rows_to_dicts(
        rows
    )

    # Korelasyon işlemini çalıştırıyoruz.
    correlations = engine.correlate(
        events
    )

    print("Mini SIEM Correlation Test Sonucu")
    print("---------------------------------")

    print(
        "Toplam Event:",
        len(events)
    )

    print(
        "Bulunan Correlation:",
        len(correlations)
    )

    print()

    for correlation in correlations:

        print(
            "Rule:",
            correlation["rule_id"]
        )

        print(
            "Name:",
            correlation["name"]
        )

        print(
            "Severity:",
            correlation["severity"]
        )

        print(
            "Event IDs:",
            correlation["event_ids"]
        )

        print(
            "Reason:",
            correlation["reason"]
        )

        print("---------------------------------")


if __name__ == "__main__":
    main()
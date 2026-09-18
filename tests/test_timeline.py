# ============================================================
# Mini SIEM - Attack Timeline Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from detection.timeline_builder import TimelineBuilder


def main():

    # Veritabanından olayları alıyoruz.
    database = DatabaseManager()

    rows = database.get_all_events()

    # Tuple kayıtlarını dictionary haline getiriyoruz.
    correlation_engine = CorrelationEngine()

    events = correlation_engine.database_rows_to_dicts(
        rows
    )

    # Timeline oluşturuyoruz.
    timeline_builder = TimelineBuilder()

    timeline = timeline_builder.build_timeline(
        events
    )

    print("Mini SIEM Attack Timeline Test Sonucu")
    print("-------------------------------------")

    print(
        "Toplam Timeline Event:",
        len(timeline)
    )

    print()

    for item in timeline:

        print(
            "Event ID:",
            item["event_id"]
        )

        print(
            "Time:",
            item["timestamp"]
        )

        print(
            "Activity:",
            item["title"]
        )

        print(
            "Source:",
            item["source"]
        )

        print(
            "Source IP:",
            item["source_ip"]
        )

        print(
            "User:",
            item["user"]
        )

        print(
            "Status:",
            item["status"]
        )

        print("-------------------------------------")


if __name__ == "__main__":
    main()
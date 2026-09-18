# ============================================================
# Mini SIEM - Detection Rules Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from detection.rules import DetectionEngine


def main():

    # Veritabanını açıyoruz.
    database = DatabaseManager()

    rows = database.get_all_events()

    # SQLite tuple kayıtlarını dictionary haline getiriyoruz.
    helper = CorrelationEngine()

    events = helper.database_rows_to_dicts(
        rows
    )

    # Detection Engine
    engine = DetectionEngine()

    detections = engine.run_all_rules(
        events
    )

    print("Mini SIEM Detection Rules Test Sonucu")
    print("------------------------------------")

    print(
        "Toplam Event:",
        len(events)
    )

    print(
        "Toplam Detection:",
        len(detections)
    )

    print()

    for detection in detections:

        print(
            "Rule:",
            detection["rule_id"]
        )

        print(
            "Name:",
            detection["name"]
        )

        print(
            "Severity:",
            detection["severity"]
        )

        print(
            "Source IP:",
            detection.get(
                "source_ip",
                ""
            )
        )

        print(
            "Event IDs:",
            detection["event_ids"]
        )

        print(
            "Reason:",
            detection["reason"]
        )

        print("------------------------------------")


if __name__ == "__main__":
    main()
# ============================================================
# Mini SIEM - Alert Engine Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from detection.alert_engine import AlertEngine


def main():

    # --------------------------------------------------------
    # VERİTABANI
    # --------------------------------------------------------

    database = DatabaseManager()

    rows = database.get_all_events()

    # --------------------------------------------------------
    # CORRELATION ENGINE
    # --------------------------------------------------------

    correlation_engine = CorrelationEngine()

    events = correlation_engine.database_rows_to_dicts(
        rows
    )

    correlations = correlation_engine.correlate(
        events
    )

    # --------------------------------------------------------
    # ALERT ENGINE
    # --------------------------------------------------------

    alert_engine = AlertEngine()

    alerts = alert_engine.generate_alerts(
        correlations
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print("Mini SIEM Alert Engine Test Sonucu")
    print("----------------------------------")

    print(
        "Toplam Event:",
        len(events)
    )

    print(
        "Toplam Correlation:",
        len(correlations)
    )

    print(
        "Toplam Alert:",
        len(alerts)
    )

    print()

    for alert in alerts:

        print(
            "Alert ID:",
            alert["alert_id"]
        )

        print(
            "Rule:",
            alert["rule_id"]
        )

        print(
            "Name:",
            alert["name"]
        )

        print(
            "Severity:",
            alert["severity"]
        )

        print(
            "Source IP:",
            alert["source_ip"]
        )

        print(
            "User:",
            alert["user"]
        )

        print(
            "Event IDs:",
            alert["event_ids"]
        )

        print(
            "Message:",
            alert["message"]
        )

        print("----------------------------------")


if __name__ == "__main__":
    main()
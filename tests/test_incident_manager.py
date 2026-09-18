# ============================================================
# Mini SIEM - Incident Manager Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from detection.alert_engine import AlertEngine
from detection.incident_manager import IncidentManager


def main():

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    database = DatabaseManager()

    rows = database.get_all_events()

    # --------------------------------------------------------
    # CORRELATION
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
    # INCIDENT MANAGER
    # --------------------------------------------------------

    incident_manager = IncidentManager()

    incidents = incident_manager.generate_incidents(
        alerts
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print("Mini SIEM Incident Manager Test Sonucu")
    print("--------------------------------------")

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

    print(
        "Toplam Incident:",
        len(incidents)
    )

    print()

    for incident in incidents:

        print(
            "Incident ID:",
            incident["incident_id"]
        )

        print(
            "Severity:",
            incident["severity"]
        )

        print(
            "Source IP:",
            incident["source_ips"]
        )

        print(
            "Users:",
            incident["users"]
        )

        print(
            "Alert IDs:",
            incident["alert_ids"]
        )

        print(
            "Rule IDs:",
            incident["rule_ids"]
        )

        print(
            "Event IDs:",
            incident["event_ids"]
        )

        print(
            "Status:",
            incident["status"]
        )

        print(
            "Description:",
            incident["description"]
        )

        print("--------------------------------------")


if __name__ == "__main__":
    main()
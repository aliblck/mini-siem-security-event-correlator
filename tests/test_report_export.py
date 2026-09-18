# ============================================================
# Mini SIEM - Incident Report Export Test
# ============================================================

from database.db_manager import DatabaseManager

from detection.correlation import CorrelationEngine
from detection.alert_engine import AlertEngine
from detection.incident_manager import IncidentManager
from detection.timeline_builder import TimelineBuilder

from reports.report_exporter import ReportExporter


def main():

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    database = DatabaseManager()

    rows = database.get_all_events()

    # --------------------------------------------------------
    # EVENTLER
    # --------------------------------------------------------

    correlation_engine = CorrelationEngine()

    events = correlation_engine.database_rows_to_dicts(
        rows
    )

    # --------------------------------------------------------
    # CORRELATION
    # --------------------------------------------------------

    correlations = correlation_engine.correlate(
        events
    )

    # --------------------------------------------------------
    # ALERT
    # --------------------------------------------------------

    alert_engine = AlertEngine()

    alerts = alert_engine.generate_alerts(
        correlations
    )

    # --------------------------------------------------------
    # INCIDENT
    # --------------------------------------------------------

    incident_manager = IncidentManager()

    incidents = incident_manager.generate_incidents(
        alerts
    )

    if not incidents:

        print(
            "Rapor oluşturulacak incident bulunamadı."
        )

        return

    incident = incidents[0]

    # --------------------------------------------------------
    # ANALYST CONCLUSION
    # --------------------------------------------------------

    # Incident için daha önce SQLite'a kaydedilmiş
    # analist değerlendirmesini alıyoruz.
    analyst_conclusion = database.get_analyst_conclusion(
        incident["incident_id"]
    )

    # Rapor oluşturulurken kullanılabilmesi için
    # incident nesnesine ekliyoruz.
    incident["analyst_conclusion"] = analyst_conclusion

    # --------------------------------------------------------
    # TIMELINE
    # --------------------------------------------------------

    timeline_builder = TimelineBuilder()

    timeline = timeline_builder.build_timeline(
        events
    )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    exporter = ReportExporter()

    report = exporter.prepare_report(
        incident=incident,
        timeline=timeline
    )

    json_path = exporter.export_json(
        report
    )

    csv_path = exporter.export_csv(
        report
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print("Mini SIEM Incident Report Test Sonucu")
    print("-------------------------------------")

    print(
        "Incident ID:",
        report["incident_id"]
    )

    print(
        "First Seen:",
        report["first_seen"]
    )

    print(
        "Last Seen:",
        report["last_seen"]
    )

    print(
        "Severity:",
        report["severity"]
    )

    print(
        "Event IDs:",
        report["event_ids"]
    )

    print(
        "Rule IDs:",
        report["rule_ids"]
    )
    print(
        "Analyst Conclusion:",
        report["analyst_conclusion"]
    )

    print()

    print(
        "JSON Rapor:",
        json_path
    )

    print(
        "CSV Rapor:",
        csv_path
    )


if __name__ == "__main__":
    main()
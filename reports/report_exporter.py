# ============================================================
# Mini SIEM - Incident Report Exporter
# Olay Raporu Dışa Aktarma Modülü
# ============================================================

import csv
import json
from pathlib import Path


class ReportExporter:
    """
    Mini SIEM tarafından oluşturulan incident kayıtlarını
    JSON ve CSV formatlarında dışa aktarır.
    """

    def __init__(self):

        # Projenin reports klasörünü buluyoruz.
        self.reports_path = (
            Path(__file__).resolve().parent
        )

        # Klasör yoksa otomatik oluşturulur.
        self.reports_path.mkdir(
            parents=True,
            exist_ok=True
        )

    # ========================================================
    # RAPOR VERİSİNİ HAZIRLAMA
    # ========================================================

    def prepare_report(
        self,
        incident,
        timeline,
        risk_score=None,
        confidence=None,
        iocs=None
    ):
        """
        Incident verisini rapor formatına dönüştürür.

        risk_score, confidence ve IOC alanları
        ilerleyen bölümlerde gerçek analiz sonuçlarıyla
        doldurulacaktır.
        """

        if iocs is None:
            iocs = []

        # ----------------------------------------------------
        # FIRST SEEN / LAST SEEN
        # ----------------------------------------------------

        first_seen = ""
        last_seen = ""

        if timeline:

            first_seen = timeline[0].get(
                "timestamp",
                ""
            )

            last_seen = timeline[-1].get(
                "timestamp",
                ""
            )

        # ----------------------------------------------------
        # TIMELINE RAPOR FORMATI
        # ----------------------------------------------------

        timeline_report = []

        for item in timeline:

            timeline_report.append(
                {
                    "event_id":
                    item.get("event_id"),

                    "timestamp":
                    item.get("timestamp", ""),

                    "activity":
                    item.get("title", ""),

                    "source":
                    item.get("source", ""),

                    "source_ip":
                    item.get("source_ip", ""),

                    "user":
                    item.get("user", ""),

                    "status":
                    item.get("status", "")
                }
            )

        # ----------------------------------------------------
        # INCIDENT RAPORU
        # ----------------------------------------------------

        report = {

            "incident_id":
            incident.get("incident_id", ""),

            "first_seen":
            first_seen,

            "last_seen":
            last_seen,

            "severity":
            incident.get("severity", ""),

            "status":
            incident.get("status", ""),

            "source_ips":
            incident.get("source_ips", []),

            "users":
            incident.get("users", []),

            "rule_ids":
            incident.get("rule_ids", []),

            "alert_ids":
            incident.get("alert_ids", []),

            "event_ids":
            incident.get("event_ids", []),

            # Sonraki bölümlerde doldurulacak.
            "iocs":
            iocs,

            "risk_score":
            risk_score,

            "confidence":
            confidence,

            "timeline":
            timeline_report,

            "analyst_conclusion":
            incident.get(
                "analyst_conclusion",
                ""
            ),

            "description":
            incident.get(
                "description",
                ""
            )
        }

        return report

    # ========================================================
    # JSON EXPORT
    # ========================================================

    def export_json(self, report):
        """
        Incident raporunu JSON dosyasına kaydeder.
        """

        incident_id = report.get(
            "incident_id",
            "INCIDENT"
        )

        file_path = (
            self.reports_path
            / f"{incident_id}.json"
        )

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                ensure_ascii=False,
                indent=4
            )

        return file_path

    # ========================================================
    # CSV EXPORT
    # ========================================================

    def export_csv(self, report):
        """
        Incident raporunun özetini CSV dosyasına kaydeder.
        """

        file_path = (
            self.reports_path
            / "incidents.csv"
        )

        fieldnames = [
            "incident_id",
            "first_seen",
            "last_seen",
            "severity",
            "status",
            "source_ips",
            "users",
            "rule_ids",
            "alert_ids",
            "event_ids",
            "iocs",
            "risk_score",
            "confidence",
            "analyst_conclusion",
            "description"
        ]

        # utf-8-sig kullanmamızın nedeni:
        # CSV dosyası Excel'de açıldığında
        # Türkçe karakterlerin düzgün görünmesidir.
        with open(
            file_path,
            "w",
            encoding="utf-8-sig",
            newline=""
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()

            writer.writerow(
                {
                    "incident_id":
                    report["incident_id"],

                    "first_seen":
                    report["first_seen"],

                    "last_seen":
                    report["last_seen"],

                    "severity":
                    report["severity"],

                    "status":
                    report["status"],

                    "source_ips":
                    ", ".join(
                        report["source_ips"]
                    ),

                    "users":
                    ", ".join(
                        report["users"]
                    ),

                    "rule_ids":
                    ", ".join(
                        report["rule_ids"]
                    ),

                    "alert_ids":
                    ", ".join(
                        report["alert_ids"]
                    ),

                    "event_ids":
                    ", ".join(
                        str(event_id)
                        for event_id
                        in report["event_ids"]
                    ),

                    "iocs":
                    ", ".join(
                        str(ioc)
                        for ioc
                        in report["iocs"]
                    ),

                    "risk_score":
                    (
                        ""
                        if report["risk_score"] is None
                        else report["risk_score"]
                    ),

                    "confidence":
                    (
                        ""
                        if report["confidence"] is None
                        else report["confidence"]
                    ),

                    "analyst_conclusion":
                    report["analyst_conclusion"],

                    "description":
                    report["description"]
                }
            )

        return file_path
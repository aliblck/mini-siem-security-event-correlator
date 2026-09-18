# ============================================================
# Mini SIEM - Evidence Matrix
# Delil Matrisi
# ============================================================

import csv
from pathlib import Path

from detection.attacker_reconstruction import AttackerReconstructor


class EvidenceMatrixBuilder:
    """
    Normalize edilmiş eventlerden adli delil matrisi oluşturur.

    Her satır:
    - Delil numarası
    - Event ID
    - Timestamp
    - Log kaynağı
    - Source IP
    - User
    - Event Type
    - Attack Stage
    - Finding
    - Forensic Value

    bilgilerini içerir.
    """

    def __init__(self):

        self.reconstructor = AttackerReconstructor()

        self.reports_path = (
            Path(__file__).resolve().parent
        )

    # ========================================================
    # LOG KAYNAĞININ ADLİ ÖNEMİ
    # ========================================================

    def get_forensic_value(self, event):
        """
        Event'in geldiği log kaynağına göre
        adli önem açıklaması döndürür.
        """

        source = event.get(
            "source",
            ""
        )

        if source == "apache_access":

            return (
                "Kaynak IP, HTTP isteği, URL, zaman ve "
                "durum kodunun belirlenmesini destekler."
            )

        if source == "auth":

            return (
                "Kimlik doğrulama denemesi, kullanıcı ve "
                "kaynak IP ilişkisinin belirlenmesini destekler."
            )

        if source == "system":

            return (
                "Sistem üzerinde gerçekleşen kullanıcı veya "
                "süreç aktivitesinin incelenmesini destekler."
            )

        if source in (
            "application",
            "tomcat",
            "ajp"
        ):

            return (
                "Uygulama seviyesindeki hata, anomali veya "
                "servis aktivitesinin incelenmesini destekler."
            )

        if source == "filesystem":

            return (
                "Dosya oluşturma veya değiştirme gibi "
                "dosya sistemi aktivitelerini destekler."
            )

        if source == "network":

            return (
                "Kaynak ve hedef sistemler arasındaki ağ "
                "iletişiminin incelenmesini destekler."
            )

        return (
            "Olayın zaman, kaynak ve aktivite bilgilerini "
            "destekleyen yardımcı delildir."
        )

    # ========================================================
    # FINDING / BULGU
    # ========================================================

    def get_finding(self, event):
        """
        Event'i kısa ve anlaşılır bir bulguya dönüştürür.
        """

        event_type = event.get(
            "event_type",
            ""
        )

        if event_type == "web_request":

            method = event.get(
                "method",
                ""
            )

            url = event.get(
                "url",
                ""
            )

            status = event.get(
                "status",
                ""
            )

            return (
                f"{method} {url} "
                f"HTTP Status={status}"
            )

        if event_type == "authentication":

            user = event.get(
                "user",
                ""
            )

            status = event.get(
                "status",
                ""
            )

            return (
                f"Authentication attempt "
                f"user={user} status={status}"
            )

        if event_type == "system_activity":

            message = event.get(
                "message",
                ""
            )

            if message:
                return message

            return "System activity detected"

        if event_type == "file_activity":

            message = event.get(
                "message",
                ""
            )

            if message:
                return message

            return "File system activity detected"

        message = event.get(
            "message",
            ""
        )

        if message:
            return message

        return event_type

    # ========================================================
    # EVIDENCE MATRIX OLUŞTUR
    # ========================================================

    def build(self, events):
        """
        Event listesinden Evidence Matrix oluşturur.
        """

        matrix = []

        for number, event in enumerate(
            events,
            start=1
        ):

            matrix.append(
                {
                    "evidence_id":
                    f"EVID-{number:03d}",

                    "event_id":
                    event.get("id"),

                    "timestamp":
                    event.get("timestamp", ""),

                    "source":
                    event.get("source", ""),

                    "source_ip":
                    event.get("source_ip", ""),

                    "user":
                    event.get("user", ""),

                    "event_type":
                    event.get("event_type", ""),

                    "attack_stage":
                    self.reconstructor.identify_stage(
                        event
                    ),

                    "finding":
                    self.get_finding(event),

                    "forensic_value":
                    self.get_forensic_value(event)
                }
            )

        return matrix

    # ========================================================
    # CSV EXPORT
    # ========================================================

    def export_csv(self, matrix):
        """
        Evidence Matrix'i CSV dosyasına aktarır.
        """

        output_path = (
            self.reports_path
            / "evidence_matrix.csv"
        )

        fieldnames = [
            "evidence_id",
            "event_id",
            "timestamp",
            "source",
            "source_ip",
            "user",
            "event_type",
            "attack_stage",
            "finding",
            "forensic_value"
        ]

        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()

            writer.writerows(
                matrix
            )

        return output_path
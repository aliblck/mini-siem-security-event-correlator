# ============================================================
# Mini SIEM - Attacker Activity Reconstruction
# Saldırgan Aktivitesinin Yeniden Oluşturulması
# ============================================================

from detection.correlation import CorrelationEngine


class AttackerReconstructor:
    """
    Normalize edilmiş eventleri zaman sırasına koyarak
    saldırgan aktivitesini yeniden oluşturur.

    Her event uygun saldırı aşaması ile etiketlenir.
    """

    def __init__(self):

        # Timestamp işlemleri için mevcut
        # Correlation Engine'i kullanıyoruz.
        self.time_helper = CorrelationEngine()

    # ========================================================
    # ŞÜPHELİ WEB İSTEĞİ KONTROLÜ
    # ========================================================

    def is_suspicious_web_request(self, event):
        """
        URL veya User-Agent içinde şüpheli gösterge
        bulunup bulunmadığını kontrol eder.
        """

        url = str(
            event.get("url", "")
        ).lower()

        user_agent = str(
            event.get("user_agent", "")
        ).lower()

        combined_text = (
            url + " " + user_agent
        )

        suspicious_patterns = [
            "' or ",
            "%27",
            "union select",
            "../",
            "<script",
            "suspicious"
        ]

        return any(
            pattern in combined_text
            for pattern in suspicious_patterns
        )

    # ========================================================
    # EVENT -> ATTACK STAGE
    # ========================================================

    def identify_stage(self, event):
        """
        Event tipine göre saldırı aşamasını belirler.
        """

        event_type = event.get(
            "event_type",
            ""
        )

        # Reconnaissance
        if event_type in (
            "reconnaissance",
            "network_scan"
        ):
            return "Reconnaissance / Keşif"

        # Web
        if event_type == "web_request":

            if self.is_suspicious_web_request(
                event
            ):
                return (
                    "Suspicious Request / "
                    "Şüpheli Web İsteği"
                )

            return (
                "Web Enumeration / "
                "Web Keşfi"
            )

        # Authentication
        if (
            event_type == "authentication"
            and
            event.get("status") == "failed"
        ):
            return (
                "Authentication Attempt / "
                "Kimlik Doğrulama Denemesi"
            )

        # Application
        if event_type in (
            "application_activity",
            "application_anomaly",
            "ajp_anomaly"
        ):
            return (
                "Application Activity / "
                "Uygulama Aktivitesi"
            )

        # System
        if event_type == "system_activity":
            return (
                "System Activity / "
                "Sistem Aktivitesi"
            )

        # File
        if event_type == "file_activity":
            return (
                "File Activity / "
                "Dosya Aktivitesi"
            )

        return "Other Activity / Diğer Aktivite"

    # ========================================================
    # RECONSTRUCTION
    # ========================================================

    def reconstruct(self, events):
        """
        Eventleri kronolojik sıraya koyarak
        saldırgan aktivite zincirini oluşturur.
        """

        default_year = self.time_helper.find_default_year(
            events
        )

        reconstructed_events = []

        for event in events:

            parsed_time = self.time_helper.parse_timestamp(
                event.get("timestamp", ""),
                default_year
            )

            # Timestamp çözülemiyorsa event'i atlamıyoruz.
            # Sadece sıralamada en sona bırakıyoruz.
            reconstructed_events.append(
                {
                    "event_id":
                    event.get("id"),

                    "timestamp":
                    event.get("timestamp", ""),

                    "parsed_time":
                    parsed_time,

                    "stage":
                    self.identify_stage(event),

                    "source":
                    event.get("source", ""),

                    "source_ip":
                    event.get("source_ip", ""),

                    "user":
                    event.get("user", ""),

                    "event_type":
                    event.get("event_type", ""),

                    "status":
                    event.get("status", ""),

                    "url":
                    event.get("url", ""),

                    "message":
                    event.get("message", "")
                }
            )

        # Timestamp bulunan kayıtlar önce,
        # bulunmayanlar en son sıralanır.
        reconstructed_events.sort(
            key=lambda item: (
                item["parsed_time"] is None,
                item["parsed_time"]
            )
        )

        # Tekrarlanan aşamaların sayısını hesaplıyoruz.
        stage_counts = {}

        for item in reconstructed_events:

            stage = item["stage"]

            stage_counts[stage] = (
                stage_counts.get(stage, 0) + 1
            )

        source_ips = sorted(
            {
                item["source_ip"]
                for item in reconstructed_events
                if item["source_ip"]
            }
        )

        users = sorted(
            {
                item["user"]
                for item in reconstructed_events
                if item["user"]
            }
        )

        first_seen = ""

        last_seen = ""

        if reconstructed_events:

            first_seen = reconstructed_events[0][
                "timestamp"
            ]

            last_seen = reconstructed_events[-1][
                "timestamp"
            ]

        return {
            "first_seen": first_seen,
            "last_seen": last_seen,
            "source_ips": source_ips,
            "users": users,
            "stage_counts": stage_counts,
            "timeline": reconstructed_events
        }
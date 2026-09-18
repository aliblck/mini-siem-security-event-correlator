# ============================================================
# Mini SIEM - Incident Manager
# Vaka Yönetim Modülü
# ============================================================


class IncidentManager:
    """
    Alert Engine tarafından oluşturulan alarmları
    güvenlik vakaları (incident) altında toplar.

    Bir incident içerisinde:

    - Incident ID
    - Severity
    - Source IP
    - User
    - İlgili Alert ID'leri
    - İlgili Event ID'leri
    - Rule ID'leri
    - Açıklama

    tutulur.
    """

    def __init__(self):

        # INCIDENT-001, INCIDENT-002 gibi
        # numaralar üretmek için kullanılır.
        self.incident_counter = 0

    # ========================================================
    # SEVERITY KARŞILAŞTIRMA
    # ========================================================

    def severity_score(self, severity):
        """
        Severity değerlerini sayısal puana çevirir.

        Böylece bir incident içinde birden fazla alarm varsa
        en yüksek severity seçilebilir.
        """

        severity_map = {
            "LOW": 1,
            "MEDIUM": 2,
            "MEDIUM-HIGH": 3,
            "HIGH": 4,
            "CRITICAL": 5
        }

        return severity_map.get(
            severity,
            0
        )

    # ========================================================
    # TEK INCIDENT OLUŞTURMA
    # ========================================================

    def create_incident(self, alerts):
        """
        Birbiriyle ilişkili alertleri tek incident altında toplar.
        """

        if not alerts:
            return None

        self.incident_counter += 1

        incident_id = (
            f"INCIDENT-{self.incident_counter:03d}"
        )

        # ----------------------------------------------------
        # EN YÜKSEK SEVERITY
        # ----------------------------------------------------

        highest_alert = max(
            alerts,
            key=lambda alert: self.severity_score(
                alert.get("severity", "")
            )
        )

        highest_severity = highest_alert.get(
            "severity",
            "LOW"
        )

        # ----------------------------------------------------
        # SOURCE IP
        # ----------------------------------------------------

        source_ips = []

        for alert in alerts:

            source_ip = alert.get(
                "source_ip",
                ""
            )

            if (
                source_ip
                and
                source_ip not in source_ips
            ):
                source_ips.append(
                    source_ip
                )

        # ----------------------------------------------------
        # USER
        # ----------------------------------------------------

        users = []

        for alert in alerts:

            user = alert.get(
                "user",
                ""
            )

            if (
                user
                and
                user not in users
            ):
                users.append(
                    user
                )

        # ----------------------------------------------------
        # ALERT ID
        # ----------------------------------------------------

        alert_ids = []

        for alert in alerts:

            alert_id = alert.get(
                "alert_id"
            )

            if alert_id:
                alert_ids.append(
                    alert_id
                )

        # ----------------------------------------------------
        # RULE ID
        # ----------------------------------------------------

        rule_ids = []

        for alert in alerts:

            rule_id = alert.get(
                "rule_id"
            )

            if (
                rule_id
                and
                rule_id not in rule_ids
            ):
                rule_ids.append(
                    rule_id
                )

        # ----------------------------------------------------
        # EVENT ID
        # ----------------------------------------------------

        event_ids = []

        for alert in alerts:

            for event_id in alert.get(
                "event_ids",
                []
            ):

                if event_id not in event_ids:
                    event_ids.append(
                        event_id
                    )

        # Event ID'leri küçükten büyüğe sıralıyoruz.
        event_ids.sort()

        # ----------------------------------------------------
        # INCIDENT NESNESİ
        # ----------------------------------------------------

        incident = {

            "incident_id":
            incident_id,

            "severity":
            highest_severity,

            "source_ips":
            source_ips,

            "users":
            users,

            "alert_ids":
            alert_ids,

            "rule_ids":
            rule_ids,

            "event_ids":
            event_ids,

            "alert_count":
            len(alerts),

            "status":
            "OPEN",

            "analyst_conclusion":
            "",

            "description":
            (
                f"{len(alerts)} ilişkili güvenlik alarmı "
                f"tek vaka altında toplandı."
            )
        }

        return incident

    # ========================================================
    # INCIDENT ÜRETME
    # ========================================================

    def generate_incidents(self, alerts):
        """
        Şimdilik tüm ilişkili alarmları tek incident altında toplar.

        Daha ileride birden fazla saldırgan IP veya farklı
        saldırı zincirleri olduğunda ayrı incidentler
        oluşturabilecek şekilde genişletilebilir.
        """

        incidents = []

        if not alerts:
            return incidents

        incident = self.create_incident(
            alerts
        )

        if incident is not None:
            incidents.append(
                incident
            )

        return incidents
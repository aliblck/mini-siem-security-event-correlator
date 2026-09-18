# ============================================================
# Mini SIEM - Alert Engine
# Alarm Üretim Motoru
# ============================================================


class AlertEngine:
    """
    Correlation Engine tarafından bulunan ilişkilerden
    güvenlik alarmı üretir.

    Her alarmda:

    - Alert ID
    - Severity
    - Rule ID
    - Alarm adı
    - Source IP
    - User
    - İlişkili Event ID'leri
    - Açıklama

    gibi bilgiler tutulur.
    """

    def __init__(self):

        # Oluşturulan alarm numarasını takip eder.
        self.alert_counter = 0

    # ========================================================
    # TEK ALARM OLUŞTURMA
    # ========================================================

    def create_alert(self, correlation):
        """
        Tek bir correlation kaydını alarma dönüştürür.
        """

        self.alert_counter += 1

        # ALERT-001, ALERT-002 şeklinde ID oluşturuyoruz.
        alert_id = f"ALERT-{self.alert_counter:03d}"

        alert = {
            "alert_id": alert_id,

            "rule_id":
            correlation.get("rule_id", ""),

            "name":
            correlation.get("name", ""),

            "severity":
            correlation.get("severity", "LOW"),

            "source_ip":
            correlation.get("source_ip", ""),

            "user":
            correlation.get("user", ""),

            "process":
            correlation.get("process", ""),

            "event_ids":
            correlation.get("event_ids", []),

            "message":
            correlation.get("reason", "")
        }

        return alert

    # ========================================================
    # TÜM ALARMLARI OLUŞTURMA
    # ========================================================

    def generate_alerts(self, correlations):
        """
        Correlation Engine çıktılarının tamamını
        alarm listesine dönüştürür.
        """

        alerts = []

        for correlation in correlations:

            alert = self.create_alert(
                correlation
            )

            alerts.append(
                alert
            )

        return alerts
    
# ============================================================
# Mini SIEM - Risk Scoring Engine
# Risk Puanlama Motoru
# ============================================================


class RiskScorer:
    """
    Event, Detection ve Correlation sonuçlarını kullanarak
    güvenlik vakası için 0-100 arasında risk puanı üretir.

    Risk seviyeleri:

    0 - 25   -> LOW
    26 - 50  -> MEDIUM
    51 - 75  -> HIGH
    76 - 100 -> CRITICAL
    """

    # ========================================================
    # RISK LEVEL
    # ========================================================

    def get_risk_level(self, score):
        """
        Sayısal risk puanını severity seviyesine dönüştürür.
        """

        if score <= 25:
            return "LOW"

        if score <= 50:
            return "MEDIUM"

        if score <= 75:
            return "HIGH"

        return "CRITICAL"

    # ========================================================
    # ANA RISK HESAPLAMA
    # ========================================================

    def calculate(
        self,
        events,
        detections,
        correlations
    ):
        """
        Event, Detection ve Correlation sonuçlarından
        toplam risk puanını hesaplar.
        """

        score = 0

        # Hangi puanın neden verildiğini göstermek için.
        breakdown = []

        # ----------------------------------------------------
        # DETECTION RULE ID'LERİ
        # ----------------------------------------------------

        detection_rule_ids = {
            detection.get("rule_id")
            for detection in detections
        }

        # ----------------------------------------------------
        # CORRELATION RULE ID'LERİ
        # ----------------------------------------------------

        correlation_rule_ids = {
            correlation.get("rule_id")
            for correlation in correlations
        }

        # ====================================================
        # WEB ENUMERATION
        # ====================================================

        if "DET-001" in detection_rule_ids:

            score += 10

            breakdown.append(
                {
                    "reason": "Web Enumeration",
                    "points": 10
                }
            )

        # ====================================================
        # SUSPICIOUS REQUEST
        # ====================================================

        if "DET-002" in detection_rule_ids:

            score += 20

            breakdown.append(
                {
                    "reason": "Suspicious Web Request",
                    "points": 20
                }
            )

        # ====================================================
        # AUTHENTICATION
        # ====================================================

        # Eğer çoklu başarısız authentication tespit edilmişse
        # 20 puan veriyoruz.
        if "DET-003" in detection_rule_ids:

            score += 20

            breakdown.append(
                {
                    "reason":
                    "Multiple Failed Authentication",

                    "points": 20
                }
            )

        else:

            # Çoklu saldırı yoksa sadece tek başarısız
            # authentication olayı için 10 puan veriyoruz.

            single_failed_auth = any(
                event.get("event_type") == "authentication"
                and
                event.get("status") == "failed"
                for event in events
            )

            if single_failed_auth:

                score += 10

                breakdown.append(
                    {
                        "reason":
                        "Single Failed Authentication",

                        "points": 10
                    }
                )

        # ====================================================
        # RECONNAISSANCE
        # ====================================================

        reconnaissance = any(
            event.get("event_type")
            in (
                "reconnaissance",
                "network_scan"
            )
            for event in events
        )

        if reconnaissance:

            score += 10

            breakdown.append(
                {
                    "reason": "Reconnaissance",
                    "points": 10
                }
            )

        # ====================================================
        # APPLICATION / AJP ANOMALY
        # ====================================================

        application_anomaly = any(
            event.get("event_type")
            in (
                "application_anomaly",
                "ajp_anomaly"
            )
            for event in events
        )

        if application_anomaly:

            score += 15

            breakdown.append(
                {
                    "reason": "Application / AJP Anomaly",
                    "points": 15
                }
            )

        # ====================================================
        # SYSTEM ACTIVITY
        # ====================================================

        system_activity = any(
            event.get("event_type") == "system_activity"
            for event in events
        )

        if system_activity:

            score += 10

            breakdown.append(
                {
                    "reason": "System Activity",
                    "points": 10
                }
            )

        # ====================================================
        # FILE ACTIVITY
        # ====================================================

        file_activity = any(
            event.get("event_type") == "file_activity"
            for event in events
        )

        if file_activity:

            score += 15

            breakdown.append(
                {
                    "reason": "File Activity",
                    "points": 15
                }
            )

        # ====================================================
        # CORRELATION BONUS
        # WEB -> FAILED SSH
        # ====================================================

        if "CORR-001" in correlation_rule_ids:

            score += 10

            breakdown.append(
                {
                    "reason":
                    "Web → Failed Authentication Correlation",

                    "points": 10
                }
            )

        # ====================================================
        # MAKSİMUM PUAN
        # ====================================================

        # Risk puanı 100'ü geçemez.
        score = min(
            score,
            100
        )

        risk_level = self.get_risk_level(
            score
        )

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "breakdown": breakdown
        }
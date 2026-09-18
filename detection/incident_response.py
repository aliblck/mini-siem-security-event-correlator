# ============================================================
# Mini SIEM - Incident Response Engine
# Olay Müdahale Motoru
# ============================================================


class IncidentResponseEngine:
    """
    Incident severity ve tetiklenen güvenlik kurallarına göre
    olay müdahale önerileri oluşturur.

    Bu modül herhangi bir sistemi otomatik olarak engellemez.
    Sadece güvenlik analistine uygulanabilecek adımları önerir.
    """

    def generate_response(
        self,
        incident,
        detections=None,
        correlations=None
    ):
        """
        Incident için response planı oluşturur.
        """

        if detections is None:
            detections = []

        if correlations is None:
            correlations = []

        severity = incident.get(
            "severity",
            "LOW"
        )

        detection_ids = {
            detection.get("rule_id")
            for detection in detections
        }

        correlation_ids = {
            correlation.get("rule_id")
            for correlation in correlations
        }

        actions = []

        # ====================================================
        # 1. EVIDENCE PRESERVATION
        # DELİLLERİN KORUNMASI
        # ====================================================

        actions.append(
            {
                "phase": "Evidence Preservation",
                "action":
                "İlgili log, veritabanı kayıtları ve "
                "zaman çizelgesi korunmalıdır.",
                "priority": "HIGH"
            }
        )

        # ====================================================
        # 2. SOURCE IP
        # ====================================================

        source_ips = incident.get(
            "source_ips",
            []
        )

        if source_ips:

            actions.append(
                {
                    "phase": "Containment",
                    "action":
                    (
                        "Şüpheli kaynak IP adresi izlenmeli "
                        "ve olay doğrulanırsa ağ politikalarına "
                        "uygun şekilde geçici olarak "
                        "engellenmesi değerlendirilmelidir."
                    ),
                    "priority": "HIGH"
                }
            )

        # ====================================================
        # 3. WEB ENUMERATION
        # ====================================================

        if "DET-001" in detection_ids:

            actions.append(
                {
                    "phase": "Investigation",
                    "action":
                    (
                        "Kaynak IP'nin eriştiği URL'ler ve "
                        "istek yoğunluğu incelenmelidir."
                    ),
                    "priority": "MEDIUM"
                }
            )

        # ====================================================
        # 4. SUSPICIOUS WEB REQUEST
        # ====================================================

        if "DET-002" in detection_ids:

            actions.append(
                {
                    "phase": "Containment",
                    "action":
                    (
                        "Şüpheli HTTP isteği incelenmeli, "
                        "hedef web uygulamasında güvenlik açığı "
                        "ve başarılı istismar belirtisi "
                        "araştırılmalıdır."
                    ),
                    "priority": "HIGH"
                }
            )

        # ====================================================
        # 5. AUTHENTICATION ATTACK
        # ====================================================

        if "DET-003" in detection_ids:

            actions.append(
                {
                    "phase": "Containment",
                    "action":
                    (
                        "Hedef kullanıcı hesabı ve SSH "
                        "kimlik doğrulama kayıtları "
                        "incelenmelidir."
                    ),
                    "priority": "HIGH"
                }
            )

            actions.append(
                {
                    "phase": "Prevention",
                    "action":
                    (
                        "Başarısız giriş eşiği, hesap kilitleme "
                        "ve SSH erişim politikaları "
                        "gözden geçirilmelidir."
                    ),
                    "priority": "MEDIUM"
                }
            )

        # ====================================================
        # 6. WEB → AUTH CORRELATION
        # ====================================================

        if "CORR-001" in correlation_ids:

            actions.append(
                {
                    "phase": "Investigation",
                    "action":
                    (
                        "Web aktivitesi ile başarısız SSH "
                        "girişleri aynı kaynak IP üzerinden "
                        "birlikte incelenmelidir."
                    ),
                    "priority": "HIGH"
                }
            )

        # ====================================================
        # 7. CRITICAL INCIDENT
        # ====================================================

        if severity == "CRITICAL":

            actions.append(
                {
                    "phase": "Escalation",
                    "action":
                    (
                        "Vaka kritik seviyede olduğu için "
                        "üst seviye güvenlik incelemesine "
                        "aktarılmalıdır."
                    ),
                    "priority": "CRITICAL"
                }
            )

            actions.append(
                {
                    "phase": "Recovery",
                    "action":
                    (
                        "Etkilenen servislerin bütünlüğü "
                        "doğrulanmalı ve olay sonrası "
                        "kontroller gerçekleştirilmelidir."
                    ),
                    "priority": "HIGH"
                }
            )

        return {
            "incident_id":
            incident.get("incident_id", ""),

            "severity":
            severity,

            "source_ips":
            source_ips,

            "action_count":
            len(actions),

            "actions":
            actions
        }
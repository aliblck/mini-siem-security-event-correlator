# ============================================================
# Mini SIEM - Attack vs Normal Comparison
# Görev 29
# ============================================================

from detection.rules import DetectionEngine
from detection.correlation import CorrelationEngine
from detection.risk import RiskScorer


def analyze_scenario(events):
    """
    Verilen event listesini analiz eder.

    Sonuç olarak:
    - Event sayısı
    - Detection sayısı
    - Correlation sayısı
    - Risk Score
    - Risk Level

    değerlerini döndürür.
    """

    detection_engine = DetectionEngine()
    correlation_engine = CorrelationEngine()
    risk_scorer = RiskScorer()

    # Detection kurallarını çalıştır.
    detections = detection_engine.run_all_rules(
        events
    )

    # Correlation kurallarını çalıştır.
    correlations = correlation_engine.correlate(
        events
    )

    # Risk puanını hesapla.
    risk_result = risk_scorer.calculate(
        events=events,
        detections=detections,
        correlations=correlations
    )

    return {
        "event_count": len(events),
        "detection_count": len(detections),
        "correlation_count": len(correlations),
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "detections": detections,
        "correlations": correlations
    }


def main():

    # ========================================================
    # NORMAL USER / NORMAL KULLANICI
    # ========================================================

    normal_events = [
        {
            "id": 1,
            "timestamp": "02/Sep/2026:10:00:00 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.50",
            "event_type": "web_request",
            "method": "GET",
            "url": "/index.html",
            "user_agent": "Mozilla/5.0",
            "status": "200"
        },
        {
            "id": 2,
            "timestamp": "02/Sep/2026:10:05:00 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.50",
            "event_type": "web_request",
            "method": "GET",
            "url": "/about.html",
            "user_agent": "Mozilla/5.0",
            "status": "200"
        }
    ]

    # ========================================================
    # ATTACK / SALDIRI
    # ========================================================

    attack_events = [
        # Web Enumeration
        {
            "id": 10,
            "timestamp": "02/Sep/2026:03:11:05 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/",
            "user_agent": "MiniSIEM-Stage5/1.0",
            "status": "200"
        },
        {
            "id": 11,
            "timestamp": "02/Sep/2026:03:11:11 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/dvwa/",
            "user_agent": "MiniSIEM-Stage5/1.0",
            "status": "302"
        },
        {
            "id": 12,
            "timestamp": "02/Sep/2026:03:11:16 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/mutillidae/",
            "user_agent": "MiniSIEM-Stage5/1.0",
            "status": "200"
        },

        # Suspicious Request
        {
            "id": 13,
            "timestamp": "02/Sep/2026:03:16:36 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/dvwa/?id=1%27%20OR%20%271%27=%271",
            "user_agent":
            "MiniSIEM-Stage5-Suspicious/1.0",
            "status": "302"
        },

        # Authentication Attack
        {
            "id": 14,
            "timestamp": "Sep 2 03:20:25",
            "source": "auth",
            "source_ip": "192.168.14.128",
            "user": "msfadmin",
            "process": "sshd[9114]",
            "event_type": "authentication",
            "action": "login",
            "status": "failed"
        },
        {
            "id": 15,
            "timestamp": "Sep 2 03:20:45",
            "source": "auth",
            "source_ip": "192.168.14.128",
            "user": "msfadmin",
            "process": "sshd[9115]",
            "event_type": "authentication",
            "action": "login",
            "status": "failed"
        },
        {
            "id": 16,
            "timestamp": "Sep 2 03:21:05",
            "source": "auth",
            "source_ip": "192.168.14.128",
            "user": "msfadmin",
            "process": "sshd[9116]",
            "event_type": "authentication",
            "action": "login",
            "status": "failed"
        },
        {
            "id": 17,
            "timestamp": "Sep 2 03:21:25",
            "source": "auth",
            "source_ip": "192.168.14.128",
            "user": "msfadmin",
            "process": "sshd[9117]",
            "event_type": "authentication",
            "action": "login",
            "status": "failed"
        },
        {
            "id": 18,
            "timestamp": "Sep 2 03:21:45",
            "source": "auth",
            "source_ip": "192.168.14.128",
            "user": "msfadmin",
            "process": "sshd[9118]",
            "event_type": "authentication",
            "action": "login",
            "status": "failed"
        },

        # System Activity
        {
            "id": 19,
            "timestamp": "Sep 2 04:02:20",
            "source": "system",
            "source_ip": "",
            "user": "msfadmin",
            "process": "stage5_system",
            "event_type": "system_activity",
            "action": "system_activity",
            "status": "success"
        },

        # File Activity
        {
            "id": 20,
            "timestamp": "Sep 2 04:05:43",
            "source": "filesystem",
            "source_ip": "",
            "user": "msfadmin",
            "process": "",
            "event_type": "file_activity",
            "action": "file_modify",
            "status": "success"
        }
    ]

    # ========================================================
    # ANALİZ
    # ========================================================

    normal_result = analyze_scenario(
        normal_events
    )

    attack_result = analyze_scenario(
        attack_events
    )

    # ========================================================
    # KARŞILAŞTIRMA TABLOSU
    # ========================================================

    print()
    print("Mini SIEM - Attack vs Normal Comparison")
    print("=" * 76)

    print(
        f"{'Metric':<25}"
        f"{'Normal User':<20}"
        f"{'Attack':<20}"
    )

    print("-" * 76)

    print(
        f"{'Event Count':<25}"
        f"{normal_result['event_count']:<20}"
        f"{attack_result['event_count']:<20}"
    )

    print(
        f"{'Detection Count':<25}"
        f"{normal_result['detection_count']:<20}"
        f"{attack_result['detection_count']:<20}"
    )

    print(
        f"{'Correlation Count':<25}"
        f"{normal_result['correlation_count']:<20}"
        f"{attack_result['correlation_count']:<20}"
    )

    print(
        f"{'Risk Score':<25}"
        f"{normal_result['risk_score']:<20}"
        f"{attack_result['risk_score']:<20}"
    )

    print(
        f"{'Risk Level':<25}"
        f"{normal_result['risk_level']:<20}"
        f"{attack_result['risk_level']:<20}"
    )

    print("=" * 76)

    # ========================================================
    # SONUÇ
    # ========================================================

    if (
        normal_result["detection_count"] == 0
        and
        normal_result["risk_score"] == 0
    ):
        normal_status = "NORMAL"
    else:
        normal_status = "REVIEW"

    if attack_result["risk_level"] == "CRITICAL":
        attack_status = "ATTACK / CRITICAL"
    else:
        attack_status = "SUSPICIOUS"

    print()
    print(
        "Normal User Sonucu:",
        normal_status
    )

    print(
        "Attack Sonucu:",
        attack_status
    )

    print()

    print(
        "Karşılaştırma Sonucu:"
    )

    print(
        "Normal kullanıcı davranışında detection veya "
        "anlamlı risk görülmezken saldırı senaryosunda "
        "birden fazla detection, correlation ve yüksek "
        "risk puanı oluşmuştur."
    )


if __name__ == "__main__":
    main()
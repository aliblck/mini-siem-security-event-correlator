# ============================================================
# Mini SIEM - 5 Test Scenario
# Görev 28
# ============================================================

from detection.rules import DetectionEngine
from detection.correlation import CorrelationEngine
from detection.risk import RiskScorer


# ============================================================
# SENARYO SONUCUNU BELİRLEME
# ============================================================

def determine_result(detections, correlations, risk_result):
    """
    Detection ve Risk sonuçlarına göre
    senaryonun genel alarm seviyesini belirler.

    Öncelik:
    CRITICAL Risk
        ↓
    HIGH Detection
        ↓
    MEDIUM Detection
        ↓
    CAUTION
        ↓
    NO ALERT
    """

    # Risk 76-100 ise doğrudan CRITICAL
    if risk_result["risk_level"] == "CRITICAL":
        return "CRITICAL"

    # Detection seviyelerini al
    severities = [
        detection.get("severity", "")
        for detection in detections
    ]

    if "HIGH" in severities:
        return "HIGH"

    if "MEDIUM" in severities:
        return "MEDIUM"

    # Detection yok fakat düşük seviyeli
    # şüpheli aktivite varsa dikkat uyarısı.
    if (
        not detections
        and not correlations
        and risk_result["risk_score"] > 0
    ):
        return "CAUTION"

    return "NO ALERT"


# ============================================================
# TEK SENARYO ÇALIŞTIRMA
# ============================================================

def run_scenario(name, events, expected):

    detection_engine = DetectionEngine()
    correlation_engine = CorrelationEngine()
    risk_scorer = RiskScorer()

    # Detection
    detections = detection_engine.run_all_rules(
        events
    )

    # Correlation
    correlations = correlation_engine.correlate(
        events
    )

    # Risk
    risk_result = risk_scorer.calculate(
        events=events,
        detections=detections,
        correlations=correlations
    )

    # Genel senaryo sonucu
    actual = determine_result(
        detections,
        correlations,
        risk_result
    )

    passed = actual == expected

    print()
    print("=" * 60)
    print("Scenario:", name)
    print("=" * 60)

    print("Event Sayısı:", len(events))
    print("Detection Sayısı:", len(detections))
    print("Correlation Sayısı:", len(correlations))

    print(
        "Risk Score:",
        risk_result["risk_score"]
    )

    print(
        "Risk Level:",
        risk_result["risk_level"]
    )

    print("Beklenen Sonuç:", expected)
    print("Gerçek Sonuç  :", actual)

    if passed:
        print("TEST SONUCU    : PASS")
    else:
        print("TEST SONUCU    : FAIL")

    # Detection detayları
    if detections:

        print("\nDetection Rules:")

        for detection in detections:

            print(
                "-",
                detection["rule_id"],
                detection["name"],
                "/",
                detection["severity"]
            )

    return passed


# ============================================================
# TEST SENARYOLARI
# ============================================================

def main():

    # --------------------------------------------------------
    # 1. NORMAL USER
    # --------------------------------------------------------

    normal_user = [
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
        }
    ]

    # --------------------------------------------------------
    # 2. WEB ENUMERATION
    # 30 saniye içinde 3 farklı URL
    # --------------------------------------------------------

    web_enumeration = [
        {
            "id": 10,
            "timestamp": "02/Sep/2026:10:10:00 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/",
            "user_agent": "Mozilla/5.0",
            "status": "200"
        },
        {
            "id": 11,
            "timestamp": "02/Sep/2026:10:10:05 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/dvwa/",
            "user_agent": "Mozilla/5.0",
            "status": "302"
        },
        {
            "id": 12,
            "timestamp": "02/Sep/2026:10:10:10 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/mutillidae/",
            "user_agent": "Mozilla/5.0",
            "status": "200"
        }
    ]

    # --------------------------------------------------------
    # 3. AUTHENTICATION ATTACK
    # 5 dakika içinde 5 başarısız giriş
    # --------------------------------------------------------

    authentication_attack = []

    auth_times = [
        "10:20:00",
        "10:20:20",
        "10:20:40",
        "10:21:00",
        "10:21:20"
    ]

    for index, time_value in enumerate(
        auth_times,
        start=20
    ):

        authentication_attack.append(
            {
                "id": index,
                "timestamp": f"Sep 2 {time_value}",
                "source": "auth",
                "source_ip": "192.168.14.128",
                "user": "msfadmin",
                "process": f"sshd[{9000 + index}]",
                "event_type": "authentication",
                "action": "login",
                "status": "failed",
                "port": 55076
            }
        )

    # --------------------------------------------------------
    # 4. MULTI-STAGE ATTACK
    # Web Enumeration
    # + Suspicious Request
    # + Multiple Failed Auth
    # + System Activity
    # + File Activity
    # --------------------------------------------------------

    multi_stage_attack = [
        {
            "id": 30,
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
            "id": 31,
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
            "id": 32,
            "timestamp": "02/Sep/2026:03:11:16 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/mutillidae/",
            "user_agent": "MiniSIEM-Stage5/1.0",
            "status": "200"
        },
        {
            "id": 33,
            "timestamp": "02/Sep/2026:03:16:36 -0400",
            "source": "apache_access",
            "source_ip": "192.168.14.128",
            "event_type": "web_request",
            "method": "GET",
            "url": "/dvwa/?id=1%27%20OR%20%271%27=%271",
            "user_agent":
            "MiniSIEM-Stage5-Suspicious/1.0",
            "status": "302"
        }
    ]

    # 5 başarısız authentication ekliyoruz.
    multi_auth_times = [
        "03:20:25",
        "03:20:45",
        "03:21:05",
        "03:21:25",
        "03:21:45"
    ]

    for index, time_value in enumerate(
        multi_auth_times,
        start=34
    ):

        multi_stage_attack.append(
            {
                "id": index,
                "timestamp": f"Sep 2 {time_value}",
                "source": "auth",
                "source_ip": "192.168.14.128",
                "user": "msfadmin",
                "process": f"sshd[{9100 + index}]",
                "event_type": "authentication",
                "action": "login",
                "status": "failed",
                "port": 55076
            }
        )

    # Sistem aktivitesi
    multi_stage_attack.append(
        {
            "id": 40,
            "timestamp": "Sep 2 04:02:20",
            "source": "system",
            "source_ip": "",
            "user": "msfadmin",
            "process": "stage5_system",
            "event_type": "system_activity",
            "action": "system_activity",
            "status": "success",
            "message":
            "scenario=stage5 action=system_activity"
        }
    )

    # Dosya aktivitesi
    multi_stage_attack.append(
        {
            "id": 41,
            "timestamp": "Sep 2 04:05:43",
            "source": "filesystem",
            "source_ip": "",
            "user": "msfadmin",
            "process": "",
            "event_type": "file_activity",
            "action": "file_modify",
            "status": "success",
            "message":
            "/home/msfadmin/stage5_test/stage5_file.txt"
        }
    )

    # --------------------------------------------------------
    # 5. FALSE POSITIVE
    #
    # Kullanıcı tek kez yanlış parola girmiş.
    # Tek olay olduğu için saldırı alarmı üretmemeli.
    # --------------------------------------------------------

    false_positive = [
        {
            "id": 50,
            "timestamp": "Sep 2 12:00:00",
            "source": "auth",
            "source_ip": "192.168.14.77",
            "user": "normal_user",
            "process": "sshd[10001]",
            "event_type": "authentication",
            "action": "login",
            "status": "failed",
            "port": 50000
        }
    ]

    # ========================================================
    # SENARYOLARI ÇALIŞTIR
    # ========================================================

    results = []

    results.append(
        run_scenario(
            "1 - Normal User",
            normal_user,
            "NO ALERT"
        )
    )

    results.append(
        run_scenario(
            "2 - Web Enumeration",
            web_enumeration,
            "MEDIUM"
        )
    )

    results.append(
        run_scenario(
            "3 - Authentication Attack",
            authentication_attack,
            "HIGH"
        )
    )

    results.append(
        run_scenario(
            "4 - Multi-Stage Attack",
            multi_stage_attack,
            "CRITICAL"
        )
    )

    results.append(
        run_scenario(
            "5 - False Positive",
            false_positive,
            "CAUTION"
        )
    )

    # ========================================================
    # GENEL SONUÇ
    # ========================================================

    print()
    print("=" * 60)
    print("GENEL TEST SONUCU")
    print("=" * 60)

    passed_count = sum(results)

    print(
        f"Başarılı Test: {passed_count} / {len(results)}"
    )

    if passed_count == len(results):

        print(
            "SONUÇ: TÜM SENARYOLAR BAŞARILI"
        )

    else:

        print(
            "SONUÇ: BAŞARISIZ SENARYO BULUNUYOR"
        )


if __name__ == "__main__":
    main()
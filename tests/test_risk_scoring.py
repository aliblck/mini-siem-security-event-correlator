# ============================================================
# Mini SIEM - Risk Scoring Test
# ============================================================

from database.db_manager import DatabaseManager

from detection.correlation import CorrelationEngine
from detection.rules import DetectionEngine
from detection.risk import RiskScorer


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
    # DETECTION
    # --------------------------------------------------------

    detection_engine = DetectionEngine()

    detections = detection_engine.run_all_rules(
        events
    )

    # --------------------------------------------------------
    # CORRELATION
    # --------------------------------------------------------

    correlations = correlation_engine.correlate(
        events
    )

    # --------------------------------------------------------
    # RISK SCORING
    # --------------------------------------------------------

    risk_scorer = RiskScorer()

    result = risk_scorer.calculate(
        events=events,
        detections=detections,
        correlations=correlations
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print("Mini SIEM Risk Scoring Test Sonucu")
    print("----------------------------------")

    print(
        "Risk Score:",
        result["risk_score"]
    )

    print(
        "Risk Level:",
        result["risk_level"]
    )

    print()

    print("Risk Breakdown:")

    for item in result["breakdown"]:

        print(
            f"+{item['points']} -> "
            f"{item['reason']}"
        )


if __name__ == "__main__":
    main()
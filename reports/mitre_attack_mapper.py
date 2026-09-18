# ============================================================
# Mini SIEM - MITRE ATT&CK Mapper
# MITRE ATT&CK Eşleştirme Modülü
# ============================================================

import csv
from pathlib import Path


class MitreAttackMapper:
    """
    Mini SIEM detection sonuçlarını
    MITRE ATT&CK teknikleri ile eşleştirir.

    ÖNEMLİ:
    Bu eşleştirme olayın kesin olarak gerçekleştiğini
    kanıtlamaz.

    Detection sonucunun MITRE ATT&CK üzerindeki
    olası karşılığını gösterir.
    """

    def __init__(self):

        self.reports_path = (
            Path(__file__).resolve().parent
        )

        # ----------------------------------------------------
        # DETECTION RULE -> MITRE ATT&CK
        # ----------------------------------------------------

        self.rule_mapping = {

            "DET-001": {
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "tactic": "Reconnaissance",
                "confidence": "MEDIUM",
                "reason": (
                    "Kısa zaman aralığında birden fazla "
                    "web kaynağına erişim, aktif keşif "
                    "davranışı ile ilişkilendirilebilir."
                )
            },

            "DET-002": {
                "technique_id": "T1190",
                "technique_name":
                "Exploit Public-Facing Application",

                "tactic": "Initial Access",

                "confidence": "POSSIBLE",

                "reason": (
                    "Şüpheli HTTP isteği dışarıya açık "
                    "bir web uygulamasının istismar "
                    "edilmeye çalışılmasıyla ilişkili olabilir. "
                    "Bu eşleştirme başarılı istismar "
                    "kanıtı değildir."
                )
            },

            "DET-003": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "confidence": "HIGH",
                "reason": (
                    "Kısa zaman aralığında tekrarlanan "
                    "başarısız kimlik doğrulama denemeleri "
                    "Brute Force davranışı ile uyumludur."
                )
            }
        }

    # ========================================================
    # MAPPING
    # ========================================================

    def map_detections(self, detections):
        """
        Detection sonuçlarını MITRE ATT&CK
        teknikleri ile eşleştirir.
        """

        mappings = []

        mapping_number = 1

        for detection in detections:

            rule_id = detection.get(
                "rule_id",
                ""
            )

            # Bu detection için tanımlı MITRE eşleşmesi yoksa
            # herhangi bir teknik uydurmuyoruz.
            if rule_id not in self.rule_mapping:
                continue

            mitre = self.rule_mapping[
                rule_id
            ]

            mappings.append(
                {
                    "mapping_id":
                    f"MITRE-{mapping_number:03d}",

                    "rule_id":
                    rule_id,

                    "detection_name":
                    detection.get(
                        "name",
                        ""
                    ),

                    "severity":
                    detection.get(
                        "severity",
                        ""
                    ),

                    "technique_id":
                    mitre["technique_id"],

                    "technique_name":
                    mitre["technique_name"],

                    "tactic":
                    mitre["tactic"],

                    "confidence":
                    mitre["confidence"],

                    "source_ip":
                    detection.get(
                        "source_ip",
                        ""
                    ),

                    "event_ids":
                    detection.get(
                        "event_ids",
                        []
                    ),

                    "reason":
                    mitre["reason"]
                }
            )

            mapping_number += 1

        return mappings

    # ========================================================
    # CSV EXPORT
    # ========================================================

    def export_csv(self, mappings):
        """
        MITRE ATT&CK eşleştirmelerini CSV olarak kaydeder.
        """

        output_path = (
            self.reports_path
            / "mitre_attack_mapping.csv"
        )

        fieldnames = [
            "mapping_id",
            "rule_id",
            "detection_name",
            "severity",
            "technique_id",
            "technique_name",
            "tactic",
            "confidence",
            "source_ip",
            "event_ids",
            "reason"
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

            for mapping in mappings:

                row = mapping.copy()

                row["event_ids"] = ",".join(
                    str(event_id)
                    for event_id
                    in mapping["event_ids"]
                )

                writer.writerow(
                    row
                )

        return output_path
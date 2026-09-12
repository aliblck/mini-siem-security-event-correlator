# ============================================================
# Mini SIEM - Apache Access Log Parser
# ============================================================

import re


class ApacheParser:
    """
    Apache access.log satırlarını parçalayan sınıf.

    Amaç:
    Tek bir log satırından aşağıdaki bilgileri çıkarmak:

    - Kaynak IP
    - Zaman
    - HTTP Method
    - URL
    - HTTP Protocol
    - Status Code
    - Response Size
    - Referrer
    - User-Agent
    """

    # Apache Combined Log Format için düzenli ifade (Regex)
    LOG_PATTERN = re.compile(
        r'(?P<source_ip>\S+) '
        r'\S+ '
        r'\S+ '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) '
        r'(?P<url>\S+) '
        r'(?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) '
        r'(?P<size>\S+) '
        r'"(?P<referrer>[^"]*)" '
        r'"(?P<user_agent>[^"]*)"'
    )

    def parse_line(self, line):
        """
        Tek bir Apache log satırını analiz eder.

        Başarılı olursa sözlük (dict) döndürür.
        Satır beklenen formata uymuyorsa None döndürür.
        """

        match = self.LOG_PATTERN.match(line.strip())

        # Log formatı eşleşmediyse
        if not match:
            return None

        # Regex ile bulunan alanları sözlük haline getiriyoruz.
        event = match.groupdict()

        # HTTP status kodunu sayı haline getiriyoruz.
        event["status"] = int(event["status"])

        # Apache'de response size bazen "-" olabilir.
        if event["size"] == "-":
            event["size"] = 0
        else:
            event["size"] = int(event["size"])

        # Kaynağın Apache olduğunu ayrıca belirtiyoruz.
        event["source"] = "apache_access"

        return event


    def parse_file(self, file_path):
        """
        Apache access.log dosyasının tamamını okur.

        Geçerli her log satırını parse ederek
        bir liste içerisinde döndürür.
        """

        events = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:

            for line in file:

                event = self.parse_line(line)

                # Parser başarılıysa listeye ekliyoruz.
                if event is not None:
                    events.append(event)

        return events


# ============================================================
# TEST BÖLÜMÜ
# Bu dosya doğrudan çalıştırılırsa küçük bir test yapılır.
# ============================================================

if __name__ == "__main__":

    parser = ApacheParser()

    # Bu satır sadece parserın çalışmasını test etmek içindir.
    # Adli delil olarak kullanılmayacaktır.
    test_log = (
        '192.168.14.128 - - [02/Sep/2026:03:16:36 -0400] '
        '"GET /dvwa/?id=test HTTP/1.1" '
        '302 154 "-" '
        '"MiniSIEM-Stage5-Suspicious/1.0"'
    )

    sonuc = parser.parse_line(test_log)

    print("Apache Parser Test Sonucu:")
    print(sonuc)
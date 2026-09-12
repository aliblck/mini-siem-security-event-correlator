# ============================================================
# Mini SIEM - SQLite Database Manager
# ============================================================

import sqlite3
from pathlib import Path

from models.event import Event


class DatabaseManager:
    """
    Mini SIEM olaylarını SQLite veritabanında saklayan sınıf.

    Görevleri:
    - events.db veritabanını oluşturmak
    - events tablosunu oluşturmak
    - normalize edilmiş olayları kaydetmek
    - kayıtlı olayları okumak
    """

    def __init__(self):
        # events.db dosyasını database klasörü içinde oluşturuyoruz.
        self.db_path = Path(__file__).resolve().parent / "events.db"

        # Program başladığında gerekli tabloyu hazırlarız.
        self.create_table()

    def get_connection(self):
        """
        SQLite veritabanına bağlantı oluşturur.
        """

        return sqlite3.connect(self.db_path)

    def create_table(self):
        """
        events tablosu yoksa oluşturur.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT,
                source TEXT,

                source_ip TEXT,
                destination_ip TEXT,

                user TEXT,
                process TEXT,

                event_type TEXT,
                action TEXT,
                status TEXT,

                message TEXT,

                method TEXT,
                url TEXT,
                user_agent TEXT,

                port INTEGER
            )
            """
        )

        connection.commit()
        connection.close()

    def insert_event(self, event):
        """
        Bir Event nesnesini events tablosuna kaydeder.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO events (
                timestamp,
                source,
                source_ip,
                destination_ip,
                user,
                process,
                event_type,
                action,
                status,
                message,
                method,
                url,
                user_agent,
                port
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.source,
                event.source_ip,
                event.destination_ip,
                event.user,
                event.process,
                event.event_type,
                event.action,
                event.status,
                event.message,
                event.method,
                event.url,
                event.user_agent,
                event.port
            )
        )

        connection.commit()

        # Eklenen olayın veritabanı ID değerini alıyoruz.
        event_id = cursor.lastrowid

        connection.close()

        return event_id

    def get_all_events(self):
        """
        Veritabanındaki bütün olayları getirir.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            ORDER BY id ASC
            """
        )

        events = cursor.fetchall()

        connection.close()

        return events

    def get_event_count(self):
        """
        Veritabanındaki toplam olay sayısını döndürür.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM events
            """
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count


# ============================================================
# TEST BÖLÜMÜ
# ============================================================

if __name__ == "__main__":

    # DatabaseManager oluşturulduğunda events.db
    # ve events tablosu otomatik hazırlanır.
    database = DatabaseManager()

    # Test için normalize edilmiş bir Event oluşturuyoruz.
    test_event = Event(
        timestamp="Sep 2 03:20:25",
        source="auth",
        source_ip="192.168.14.128",
        user="msfadmin",
        process="sshd[9081]",
        event_type="authentication",
        action="login",
        status="failed",
        port=55076
    )

    # Olayı veritabanına kaydediyoruz.
    event_id = database.insert_event(test_event)

    print("SQLite Test Sonucu:")
    print("Eklenen Event ID:", event_id)
    print("Toplam Event Sayısı:", database.get_event_count())

    print("\nVeritabanındaki Eventler:")

    for event in database.get_all_events():
        print(event)
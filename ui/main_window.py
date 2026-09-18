# ============================================================
# Mini SIEM
# Ana Masaüstü Arayüzü
# ============================================================

# tkinter Python'un masaüstü arayüz oluşturma kütüphanesidir.
import tkinter as tk
from tkinter import ttk

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from detection.alert_engine import AlertEngine
from detection.incident_manager import IncidentManager
from detection.timeline_builder import TimelineBuilder

class MiniSIEMApp(tk.Tk):
    """
    Mini SIEM uygulamasının ana masaüstü penceresi.

    Bu sınıf:
    - Ana pencereyi oluşturur.
    - Sol taraftaki menüyü oluşturur.
    - Dashboard ekranını gösterir.
    - Menü butonları arasında geçiş yapılmasını sağlar.
    """

    def __init__(self):

        # Tkinter ana pencere sınıfını başlatıyoruz.
        super().__init__()

        # ====================================================
        # ANA PENCERE AYARLARI
        # ====================================================

        # Programın üst kısmında görünen pencere başlığı.
        self.title(
            "Mini SIEM - Security Event Correlator / Güvenlik Olayı İlişkilendirici"
        )

        # Program ilk açıldığında pencerenin boyutu.
        self.geometry("1200x700")

        # Pencerenin daha fazla küçültülmesini engeller.
        self.minsize(1000, 600)

        # Ana pencerenin arka plan rengi.
        self.configure(bg="#F3F4F6")

        # ====================================================
        # SOL MENÜ
        # ====================================================

        # Programın sol tarafında bulunan menü alanı.
        self.sol_menu = tk.Frame(
            self,
            bg="#1F2937",
            width=250
        )

        self.sol_menu.pack(
            side="left",
            fill="y"
        )

        # Menü alanının genişliğinin sabit kalmasını sağlar.
        self.sol_menu.pack_propagate(False)

        # ====================================================
        # UYGULAMA BAŞLIĞI
        # ====================================================

        tk.Label(
            self.sol_menu,
            text="MINI SIEM",
            bg="#1F2937",
            fg="white",
            font=("Arial", 20, "bold")
        ).pack(
            pady=(30, 5)
        )

        # İngilizce teknik ismin yanında Türkçe anlamını gösteriyoruz.
        tk.Label(
            self.sol_menu,
            text="Security Event Correlator\nGüvenlik Olayı İlişkilendirici",
            bg="#1F2937",
            fg="#D1D5DB",
            font=("Arial", 9),
            justify="center"
        ).pack(
            pady=(0, 25)
        )

        # ====================================================
        # MENÜ BUTONLARI
        # ====================================================

        self.menu_butonu_olustur(
            "Dashboard / Ana Panel",
            self.dashboard_goster
        )

        self.menu_butonu_olustur(
            "Log Import / Log Aktarımı",
            self.log_import_goster
        )

        self.menu_butonu_olustur(
            "Events / Olaylar",
            self.events_goster
        )

        self.menu_butonu_olustur(
            "Alerts / Alarmlar",
            self.alerts_goster
        )

        self.menu_butonu_olustur(
            "Incidents / Vakalar",
            self.incidents_goster
        )

        self.menu_butonu_olustur(
            "Timeline / Zaman Çizelgesi",
            self.timeline_goster
        )

        self.menu_butonu_olustur(
            "Reports / Raporlar",
            self.reports_goster
        )

        # ====================================================
        # ANA İÇERİK ALANI
        # ====================================================

        # Menüye tıklayınca açılan sayfalar burada gösterilecek.
        self.icerik_alani = tk.Frame(
            self,
            bg="#F3F4F6"
        )

        self.icerik_alani.pack(
            side="right",
            fill="both",
            expand=True
        )

        # Program açıldığında ilk olarak Dashboard gösterilir.
        self.dashboard_goster()

    # ========================================================
    # MENÜ BUTONU OLUŞTURMA
    # ========================================================

    def menu_butonu_olustur(self, yazi, komut):
        """
        Sol menüde bulunan butonları oluşturur.

        yazi:
            Butonun üzerinde görünen yazıdır.

        komut:
            Butona tıklanınca çalışacak fonksiyondur.
        """

        buton = tk.Button(
            self.sol_menu,
            text=yazi,
            command=komut,
            bg="#1F2937",
            fg="white",

            # Fare ile tıklanınca kullanılacak renkler.
            activebackground="#374151",
            activeforeground="white",

            # Butonun kenarlığını kaldırıyoruz.
            bd=0,

            # Yazıyı sola hizalıyoruz.
            anchor="w",

            padx=20,
            pady=12,

            font=("Arial", 10)
        )

        # Buton menünün yatay genişliğini tamamen kaplar.
        buton.pack(
            fill="x"
        )

    # ========================================================
    # EKRAN TEMİZLEME
    # ========================================================

    def ekrani_temizle(self):
        """
        Kullanıcı başka bir menüye geçtiğinde
        sağ taraftaki eski içeriği temizler.

        Böylece yeni sayfa aynı alan içerisinde gösterilir.
        """

        for widget in self.icerik_alani.winfo_children():
            widget.destroy()

    # ========================================================
    # DASHBOARD / ANA PANEL
    # ========================================================

    def dashboard_goster(self):
        """
        Mini SIEM uygulamasının ana özet ekranını gösterir.
        """

        # Önce eski sayfayı temizliyoruz.
        self.ekrani_temizle()

        # Sayfa başlığı.
        tk.Label(
            self.icerik_alani,
            text="Security Dashboard / Güvenlik Ana Paneli",
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(30, 10)
        )

        # Dashboard açıklaması.
        tk.Label(
            self.icerik_alani,
            text="Mini SIEM güvenlik olaylarının genel görünümü",
            bg="#F3F4F6",
            fg="#6B7280",
            font=("Arial", 11)
        ).pack(
            anchor="w",
            padx=30
        )

        # ====================================================
        # ÖZET KARTLARI
        # ====================================================

        kart_alani = tk.Frame(
            self.icerik_alani,
            bg="#F3F4F6"
        )

        kart_alani.pack(
            fill="x",
            padx=30,
            pady=30
        )

        # Şimdilik değerler 0.
        # Daha sonra SQLite veritabanından gerçek değerleri alacağız.

        self.ozet_karti_olustur(
            kart_alani,
            "Total Events\nToplam Olay",
            "0"
        )

        self.ozet_karti_olustur(
            kart_alani,
            "Alerts\nAlarmlar",
            "0"
        )

        self.ozet_karti_olustur(
            kart_alani,
            "Incidents\nVakalar",
            "0"
        )

        self.ozet_karti_olustur(
            kart_alani,
            "Critical\nKritik",
            "0"
        )

        # ====================================================
        # SON GÜVENLİK ALARMLARI
        # ====================================================

        son_alarmlar = tk.LabelFrame(
            self.icerik_alani,
            text=" Latest Security Alerts / Son Güvenlik Alarmları ",
            bg="white",
            fg="#111827",
            font=("Arial", 11, "bold")
        )

        son_alarmlar.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 30)
        )

        # Henüz detection sistemi olmadığı için bilgi mesajı gösteriyoruz.
        tk.Label(
            son_alarmlar,
            text="Henüz güvenlik alarmı bulunmuyor.",
            bg="white",
            fg="#6B7280",
            font=("Arial", 11)
        ).pack(
            pady=50
        )

    # ========================================================
    # DASHBOARD ÖZET KARTI
    # ========================================================

    def ozet_karti_olustur(self, parent, baslik, deger):
        """
        Dashboard üzerinde bulunan küçük bilgi kartlarını oluşturur.

        Örneğin:
        Total Events
        Alerts
        Incidents
        Critical
        """

        kart = tk.Frame(
            parent,
            bg="white",
            bd=1,
            relief="solid"
        )

        kart.pack(
            side="left",
            fill="both",
            expand=True,
            padx=5
        )

        # Kart başlığı.
        tk.Label(
            kart,
            text=baslik,
            bg="white",
            fg="#6B7280",
            font=("Arial", 10),
            justify="center"
        ).pack(
            pady=(20, 5)
        )

        # Kartın sayısal değeri.
        tk.Label(
            kart,
            text=deger,
            bg="white",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            pady=(0, 20)
        )

    # ========================================================
    # BASİT SAYFA GÖSTERME
    # ========================================================

    def basit_sayfa_goster(self, baslik):
        """
        Henüz içeriğini geliştirmediğimiz menülerin
        temel sayfasını gösterir.

        İlerleyen aşamalarda bu sayfaların içlerini
        gerçek özelliklerle dolduracağız.
        """

        self.ekrani_temizle()

        tk.Label(
            self.icerik_alani,
            text=baslik,
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=30
        )

     # ========================================================
    # LOG IMPORT / LOG AKTARIMI
    # ========================================================

    def log_import_goster(self):
        self.basit_sayfa_goster(
            "Log Import / Log Aktarımı"
        )

    # ========================================================
    # EVENTS / OLAYLAR
    # ========================================================

    def events_goster(self):
        self.basit_sayfa_goster(
            "Normalized Events / Normalize Edilmiş Olaylar"
        )

    # ========================================================
    # ALERTS / ALARMLAR
    # ========================================================

    def alerts_goster(self):
        self.basit_sayfa_goster(
            "Security Alerts / Güvenlik Alarmları"
        )

    # ========================================================
    # INCIDENTS / VAKALAR
    # ========================================================

    def incidents_goster(self):
        """
        Veritabanındaki olaylardan oluşturulan
        güvenlik vakalarını ekranda gösterir.
        """

        self.ekrani_temizle()

        # ----------------------------------------------------
        # BAŞLIK
        # ----------------------------------------------------

        tk.Label(
            self.icerik_alani,
            text="Incidents / Güvenlik Vakaları",
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(30, 5)
        )

        tk.Label(
            self.icerik_alani,
            text="İlişkili güvenlik alarmlarından oluşturulan vakalar",
            bg="#F3F4F6",
            fg="#6B7280",
            font=("Arial", 11)
        ).pack(
            anchor="w",
            padx=30,
            pady=(0, 20)
        )

        # ----------------------------------------------------
        # INCIDENT VERİLERİNİ OLUŞTUR
        # ----------------------------------------------------

        database = DatabaseManager()

        rows = database.get_all_events()

        correlation_engine = CorrelationEngine()

        events = correlation_engine.database_rows_to_dicts(
            rows
        )

        correlations = correlation_engine.correlate(
            events
        )

        alert_engine = AlertEngine()

        alerts = alert_engine.generate_alerts(
            correlations
        )

        incident_manager = IncidentManager()

        incidents = incident_manager.generate_incidents(
            alerts
        )

        # ----------------------------------------------------
        # ÖZET
        # ----------------------------------------------------

        tk.Label(
            self.icerik_alani,
            text=f"Toplam Incident / Vaka: {len(incidents)}",
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 11, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(0, 10)
        )

        # ----------------------------------------------------
        # INCIDENT TABLOSU
        # ----------------------------------------------------

        tablo_alani = tk.Frame(
            self.icerik_alani,
            bg="white"
        )

        tablo_alani.pack(
            fill="x",
            padx=30,
            pady=(0, 20)
        )

        columns = (
            "incident_id",
            "severity",
            "source_ip",
            "user",
            "alerts",
            "status"
        )

        tablo = ttk.Treeview(
            tablo_alani,
            columns=columns,
            show="headings",
            height=6
        )

        tablo.heading(
            "incident_id",
            text="Incident ID / Vaka ID"
        )

        tablo.heading(
            "severity",
            text="Severity / Seviye"
        )

        tablo.heading(
            "source_ip",
            text="Source IP / Kaynak IP"
        )

        tablo.heading(
            "user",
            text="User / Kullanıcı"
        )

        tablo.heading(
            "alerts",
            text="Alerts / Alarmlar"
        )

        tablo.heading(
            "status",
            text="Status / Durum"
        )

        tablo.column(
            "incident_id",
            width=130
        )

        tablo.column(
            "severity",
            width=110
        )

        tablo.column(
            "source_ip",
            width=150
        )

        tablo.column(
            "user",
            width=120
        )

        tablo.column(
            "alerts",
            width=180
        )

        tablo.column(
            "status",
            width=90
        )

        tablo.pack(
            fill="x"
        )

        # ----------------------------------------------------
        # INCIDENT'LARI TABLOYA EKLE
        # ----------------------------------------------------

        for incident in incidents:

            tablo.insert(
                "",
                "end",
                iid=incident["incident_id"],
                values=(
                    incident["incident_id"],
                    incident["severity"],
                    ", ".join(incident["source_ips"]),
                    ", ".join(incident["users"]),
                    ", ".join(incident["alert_ids"]),
                    incident["status"]
                )
            )

        # ----------------------------------------------------
        # INCIDENT DETAY ALANI
        # ----------------------------------------------------

        detay_frame = tk.LabelFrame(
            self.icerik_alani,
            text=" Incident Detail / Vaka Detayı ",
            bg="white",
            fg="#111827",
            font=("Arial", 11, "bold")
        )

        detay_frame.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 10)
        )

        detay_text = tk.Text(
            detay_frame,
            height=8,
            font=("Consolas", 10),
            wrap="word"
        )

        detay_text.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        detay_text.insert(
            "1.0",
            "Detay görmek için tablodan bir incident seçin."
        )

        detay_text.config(
            state="disabled"
        )

        # ----------------------------------------------------
        # ANALYST CONCLUSION / ANALİST SONUCU
        # ----------------------------------------------------

        analyst_frame = tk.LabelFrame(
            self.icerik_alani,
            text=" Analyst Conclusion / Analist Sonucu ",
            bg="white",
            fg="#111827",
            font=("Arial", 11, "bold")
        )

        analyst_frame.pack(
            fill="x",
            padx=30,
            pady=(0, 30)
        )

        tk.Label(
            analyst_frame,
            text=(
                "Seçilen güvenlik vakası hakkındaki "
                "analist değerlendirmesini yazın:"
            ),
            bg="white",
            fg="#6B7280",
            font=("Arial", 10)
        ).pack(
            anchor="w",
            padx=10,
            pady=(10, 5)
        )

        analyst_text = tk.Text(
            analyst_frame,
            height=5,
            font=("Arial", 10),
            wrap="word"
        )

        analyst_text.pack(
            fill="x",
            padx=10,
            pady=(0, 10)
        )

        # Hangi incident'ın seçili olduğunu burada tutuyoruz.
        selected_incident_id = {
            "value": None
        }

        # Kaydetme sonucu kullanıcıya burada gösterilecek.
        save_status = tk.Label(
            analyst_frame,
            text="",
            bg="white",
            fg="#111827",
            font=("Arial", 9)
        )

        save_status.pack(
            anchor="w",
            padx=10,
            pady=(0, 5)
        )

        # ----------------------------------------------------
        # ANALİST SONUCUNU KAYDET
        # ----------------------------------------------------

        def analyst_sonucunu_kaydet():

            incident_id = selected_incident_id["value"]

            # Incident seçilmeden kayıt yapılamaz.
            if incident_id is None:

                save_status.config(
                    text=(
                        "Önce tablodan bir incident / vaka seçin."
                    )
                )

                return

            conclusion = analyst_text.get(
                "1.0",
                tk.END
            ).strip()

            database.save_analyst_conclusion(
                incident_id,
                conclusion
            )

            save_status.config(
                text=(
                    f"{incident_id} için analist sonucu kaydedildi."
                )
            )

        kaydet_butonu = tk.Button(
            analyst_frame,
            text="Save Conclusion / Analist Sonucunu Kaydet",
            command=analyst_sonucunu_kaydet,
            bg="#1F2937",
            fg="white",
            activebackground="#374151",
            activeforeground="white",
            bd=0,
            padx=15,
            pady=8,
            font=("Arial", 10, "bold")
        )

        kaydet_butonu.pack(
            anchor="e",
            padx=10,
            pady=(0, 10)
        )

        # ----------------------------------------------------
        # INCIDENT SEÇİLDİĞİNDE DETAY GÖSTER
        # ----------------------------------------------------

        def incident_secildi(event):

            selected = tablo.selection()

            if not selected:
                return

            incident_id = selected[0]

            selected_incident = None

            for incident in incidents:

                if incident["incident_id"] == incident_id:

                    selected_incident = incident
                    break

            if selected_incident is None:
                return

            # Seçilen Incident ID'yi saklıyoruz.
            selected_incident_id["value"] = incident_id

            # ------------------------------------------------
            # INCIDENT DETAYLARINI GÖSTER
            # ------------------------------------------------

            detay = (
                f"Incident ID : {selected_incident['incident_id']}\n"
                f"Severity    : {selected_incident['severity']}\n"
                f"Source IP   : {', '.join(selected_incident['source_ips'])}\n"
                f"Users       : {', '.join(selected_incident['users'])}\n"
                f"Alert IDs   : {', '.join(selected_incident['alert_ids'])}\n"
                f"Rule IDs    : {', '.join(selected_incident['rule_ids'])}\n"
                f"Event IDs   : {selected_incident['event_ids']}\n"
                f"Status      : {selected_incident['status']}\n"
                f"Description : {selected_incident['description']}"
            )

            detay_text.config(
                state="normal"
            )

            detay_text.delete(
                "1.0",
                tk.END
            )

            detay_text.insert(
                "1.0",
                detay
            )

            detay_text.config(
                state="disabled"
            )

            # ------------------------------------------------
            # KAYITLI ANALİST SONUCUNU YÜKLE
            # ------------------------------------------------

            saved_conclusion = database.get_analyst_conclusion(
                incident_id
            )

            analyst_text.delete(
                "1.0",
                tk.END
            )

            analyst_text.insert(
                "1.0",
                saved_conclusion
            )

            save_status.config(
                text=""
            )

        # Tablodan bir incident seçildiğinde fonksiyon çalışır.
        tablo.bind(
            "<<TreeviewSelect>>",
            incident_secildi
        )
    # ========================================================
    # TIMELINE / ZAMAN ÇİZELGESİ
    # ========================================================

    def timeline_goster(self):
        """
        Veritabanındaki olayları kronolojik sıraya koyarak
        saldırı zaman çizelgesini ekranda gösterir.
        """

        self.ekrani_temizle()

        # ----------------------------------------------------
        # BAŞLIK
        # ----------------------------------------------------

        tk.Label(
            self.icerik_alani,
            text="Attack Timeline / Saldırı Zaman Çizelgesi",
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(30, 5)
        )

        tk.Label(
            self.icerik_alani,
            text="Güvenlik olaylarının kronolojik sıralaması",
            bg="#F3F4F6",
            fg="#6B7280",
            font=("Arial", 11)
        ).pack(
            anchor="w",
            padx=30,
            pady=(0, 20)
        )

        # ----------------------------------------------------
        # VERİTABANINDAN EVENTLERİ AL
        # ----------------------------------------------------

        database = DatabaseManager()
        rows = database.get_all_events()

        correlation_engine = CorrelationEngine()
        events = correlation_engine.database_rows_to_dicts(rows)

        # ----------------------------------------------------
        # TIMELINE OLUŞTUR
        # ----------------------------------------------------

        timeline_builder = TimelineBuilder()
        timeline = timeline_builder.build_timeline(events)

        # ----------------------------------------------------
        # ÖZET
        # ----------------------------------------------------

        tk.Label(
            self.icerik_alani,
            text=(
                f"Toplam Timeline Event / "
                f"Zaman Çizelgesi Olayı: {len(timeline)}"
            ),
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 11, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(0, 10)
        )

        # ----------------------------------------------------
        # TIMELINE TABLOSU
        # ----------------------------------------------------

        tablo_alani = tk.Frame(
            self.icerik_alani,
            bg="white"
        )

        tablo_alani.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 30)
        )

        columns = (
            "event_id",
            "timestamp",
            "activity",
            "source",
            "source_ip",
            "user",
            "status"
        )

        tablo = ttk.Treeview(
            tablo_alani,
            columns=columns,
            show="headings"
        )

        tablo.heading("event_id", text="Event ID")
        tablo.heading("timestamp", text="Time / Zaman")
        tablo.heading("activity", text="Activity / Aktivite")
        tablo.heading("source", text="Source / Kaynak")
        tablo.heading("source_ip", text="Source IP / Kaynak IP")
        tablo.heading("user", text="User / Kullanıcı")
        tablo.heading("status", text="Status / Durum")

        tablo.column("event_id", width=70)
        tablo.column("timestamp", width=190)
        tablo.column("activity", width=260)
        tablo.column("source", width=120)
        tablo.column("source_ip", width=140)
        tablo.column("user", width=110)
        tablo.column("status", width=90)

        # ----------------------------------------------------
        # TIMELINE EVENTLERİNİ TABLOYA EKLE
        # ----------------------------------------------------

        for item in timeline:
            tablo.insert(
                "",
                "end",
                values=(
                    item["event_id"],
                    item["timestamp"],
                    item["title"],
                    item["source"],
                    item["source_ip"],
                    item["user"],
                    item["status"]
                )
            )

        # Dikey kaydırma çubuğu
        scrollbar = ttk.Scrollbar(
            tablo_alani,
            orient="vertical",
            command=tablo.yview
        )

        tablo.configure(
            yscrollcommand=scrollbar.set
        )

        tablo.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

    # ========================================================
    # REPORTS / RAPORLAR
    # ========================================================

    def reports_goster(self):
        self.basit_sayfa_goster(
            "Incident Reports / Olay Raporları"
        )

# Mini SIEM - Security Event Correlator

Bu ilk sürüm yalnızca proje iskeletini ve masaüstü arayüzünü içerir.

## Çalıştırma

VS Code içinde proje klasörünü açın ve terminalde:

```bash
python main.py
```

veya Windows'ta:

```bash
py main.py
```

## Klasörlerin amacı

- `main.py`: Uygulamayı başlatır.
- `ui/`: Masaüstü arayüzü.
- `parsers/`: Log parser dosyaları.
- `models/`: Normalize event modeli.
- `database/`: SQLite işlemleri.
- `detection/`: Detection, correlation ve risk işlemleri.
- `sample_logs/`: Test logları.
- `reports/`: Otomatik raporlar.
- `tests/`: Test senaryoları.

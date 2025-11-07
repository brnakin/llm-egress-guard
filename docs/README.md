# Documentation Index

Bu dizin, LLM Egress Guard projesindeki ana dökümanların nerede bulunduğunu ve hangi amaçlara hizmet ettiklerini hızlıca gösterir.

## Genel Bakış

| Dosya | Açıklama |
|-------|----------|
| [`README.md`](../README.md) | Projenin kurulumu, çalışma biçimi, metrikler ve Sprint durum özetleri. |
| [`NORMALIZATION_SECURITY.md`](../NORMALIZATION_SECURITY.md) | Normalizasyon katmanındaki güvenlik tedbirlerinin ayrıntılı teknik anlatımı. |
| [`docs/README.md`](./README.md) | (Bu dosya) Tüm dokümantasyonun merkezi indeksi. |

## Test & Korpus Dökümanları

| Dosya | Açıklama |
|-------|----------|
| [`tests/regression/README.md`](../tests/regression/README.md) | Regresyon korpusu kategorileri, örnek dosyalar ve golden çıktıları nasıl güncelleyeceğiniz. |
| [`tests/regression/golden_v1.jsonl`](../tests/regression/golden_v1.jsonl) | Her korpus örneği için beklenen blok/maske sonuçları. (Otomatik üretilir; önce README’yi okuyun.) |
| [`tests/regression/golden_manifest.json`](../tests/regression/golden_manifest.json) | Golden versiyon etiketi, oluşturma zamanı ve örnek sayısı kayıtları. |

## Araçlar & Scriptler

| Dosya | Açıklama |
|-------|----------|
| [`scripts/demo_policy_reload.py`](../scripts/demo_policy_reload.py) | Policy/safe-message hot-reload davranışını göstermek için interaktif script. (Kullanım: `PYTHONPATH=. python scripts/demo_policy_reload.py`.) |

## Sprint Raporları

| Dosya | Açıklama |
|-------|----------|
| [`reports/README.md`](../reports/README.md) | Sprint raporlarının dizini. |
| [`reports/Sprint-1-Report.md`](../reports/Sprint-1-Report.md) | Sprint 1 teslimleri ve kararları. |
| [`reports/Sprint-2-Report.md`](../reports/Sprint-2-Report.md) | Sprint 2 dedektör/policy çalışmaları ve açık maddeler. |

## Diğer Notlar

- CI, benchmark veya script’lerle ilgili bilgiler için `Makefile`, `ci/github-actions.yml` ve `scripts/` dizinine bakabilirsiniz.
- Yeni doküman eklediğinizde bu indeks tablosuna kısaca ekleyerek gezinilebilirliği koruyun.

# MVP doğrulama pilotu 01 — gerçek GitHub repository'leri

- **Tarih:** 2026-10-30
- **Sürüm:** AI Code Auditor 0.1.0 (commit `0ecc262`)
- **Durum:** PİLOT TAMAMLANDI — kullanıcı 2026-10-30'da kabul etti. Güvenli çalışma, hedef bütünlüğü, gizlilik, ağ izolasyonu ve hata yönetimi başarılı. Doğruluk ve rapor kalitesi eksikleri (§7) "MVP Accuracy & Reliability Hardening" planına aktarıldı. `v0.1.0` tag'i, GitHub release ve PyPI yayını bu eksikler nedeniyle ertelendi.
- **Kapsam dışı:** Bu pilot sırasında ürün kodu değişmedi; commit, tag veya release oluşturulmadı. OSV sorgusu yapılmadı (onaylanmadı).

## 1. Özet

| Soru | Sonuç |
|---|---|
| **Hedef değişti mi?** | Hayır. 3 repo × 4 senaryo boyunca dosya ve `.git` içeriği (SHA-256, boyut, mtime) bayt düzeyinde aynı kaldı. |
| **Hedef kodu çalıştı mı?** | Hayır. Auditor sürecinde hedeften import, exec veya compile olmadı. Başlatılan süreçler yalnızca 4 güvenilir executable'dı ve hiçbirinin çalışma dizini hedefin içinde değildi. |
| **İzinsiz ağ erişimi oldu mu?** | Hayır. Auditor sürecinde DNS veya bağlantı denemesi olmadı. Araç süreçlerinde loopback dışı TCP bağlantısı görülmedi. |
| **Secret sızdı mı?** | Hayır. Raporlarda ve konsolda secret değeri, değerin orta parçası, benchmark token'ı, yazar adı, e-posta ve mutlak yol bulunmadı. |
| **Hatalı COMPLETE var mı?** | Hayır. Analiz edilemeyen her nesne PARTIAL ile raporlandı. ERROR, TIMED_OUT ve CLEANUP_FAILED hiç oluşmadı. |
| **Durma koşulu** | Tetiklenmedi. |
| **Ürün hatası** | Güvenlik hatası bulunmadı. 8 doğruluk ve kullanılabilirlik bulgusu var (§7). |

**En önemli doğruluk bulguları:**

1. **Önem kalibrasyonu (P1):** Vulpy'deki istismar edilebilir SQL injection'lar yalnızca MEDIUM olarak raporlanıyor. Bu yüzden kasıtlı zafiyetli uygulama `--fail-on high` kapısından geçiyor. Buna karşılık Flask, tasarım gereği `exec`/`eval` (S102/S307, HIGH) yüzünden kapıdan kalıyor.
2. **Secret kapsamı (leaky-repo):** Gitleaks'in varsayılan kuralları, risk içeren 42 dosyanın yalnızca 14'ünde bulgu üretiyor. Risk satırlarının en fazla 22/96'sı (yaklaşık %23) eşleşiyor. Düşük entropili parolalar, hash'ler, PHP/.env/XML kimlik bilgileri, `.netrc` ve `.git-credentials` yakalanmıyor. Adaptör, doğrudan Gitleaks ile konum bazında birebir aynı sonucu veriyor; sınır motorun kural setinde.
3. **Gürültü (Flask):** Flask'ta güvenlik kategorisindeki 34 bulgunun 30'u yanlış pozitif (20'si `tests/`, 6'sı `docs/`). Git geçmişinde aynı dokümantasyon örneği (en fazla 2 farklı değer) 224 ayrı bulgu olarak listeleniyor.

### Metriklerin paydaları farklıdır

Bu belgedeki oranlar **birbiriyle karşılaştırılamaz**; her birinin payı, paydası ve birimi farklıdır. Hiçbiri Python ekosistemini temsil etmez: üç repo, elle sınıflandırma ve küçük örneklemler.

| Metrik | Birim | Pay / payda | Not |
|---|---|---|---|
| Vulpy recall 9/9 | Kod okunarak doğrulanmış açık (`bad/`) | Tespit edilen / mevcut kuralların yakalayabileceği açık | Desteklenmeyen sınıflar paydada yok (§6). Payda çok küçük (9) |
| Vulpy hassasiyeti 51/59 | Bulgu (R1 öncesi; 49 konum) | Gerçek / tüm güvenlik bulguları (`bad/`, `good/`, `utils/`) | Kasıtlı zafiyetli bir repo; gerçek dünya hassasiyetini temsil etmez |
| Flask hassasiyeti 3/34 | Bulgu | Gerçek / güvenlik kategorisindeki tüm bulgular | Bakım ve stil bulguları (17) hariç |
| leaky-repo dosya kapsamı 14/42 | Dosya | En az bir bulgusu olan / `secrets.csv`'de risk satırı olan dosya | Bulgunun risk satırında olduğu doğrulanmadı |
| leaky-repo satır kapsamı ≤ 22/96 | Satır | Dosya başına `min(bulunan satır, risk satırı)` toplamı / risk satırı | **Üst sınır**; benchmark satır numarası vermiyor |
| Geçmiş tamamlama oranları (ör. 313/319) | Git nesnesi (blob + commit mesajı) | Analiz edilen / listelenen | Kapsam ölçüsüdür, doğruluk değil |
| Çalışma ağacı oranları (ör. 113/113) | Dosya | Analiz edilen / araca uygun dosya | Araca göre değişir (Ruff/Semgrep: Python dosyası; Gitleaks: tüm dosyalar) |

## 2. Test edilen repository'ler

| Repo | Commit (HEAD) | Dal | Lisans | Dosya (izlenen) | Commit (tüm ref / HEAD) | Ref'ler | Nesne | Boyut (çalışma ağacı / `.git`) | Git yapısı |
|---|---|---|---|---|---|---|---|---|---|
| `fportantier/vulpy` | `5249cc8b05a1c37f6b2f757b1cf16a509c327122` | master | MIT | 113 | 58 / 58 | 3 uzak dal, 0 tag | 437 (1 pack) | 4,8 MB / 3,1 MB | format 0, extension yok, submodule yok, LFS yok. **2 symlink** (`*/payloads/payload.js` → `keylogger.js`) `core.symlinks=false` ile düz dosya oldu |
| `Plazmaz/leaky-repo` | `2e951359cac53addbee56437da3ffb546e3dfe24` | master | MIT | 61 | 26 / 25 | 3 uzak dal, 4 tag | 233 (1 pack) | 0,6 MB / 0,08 MB | format 0, extension, submodule, LFS ve symlink yok |
| `pallets/flask` | `d086db856be187255b8ec61ef409357393020f32` | main | BSD-3-Clause | 236 | 5603 / 5562 | 5 uzak dal, 69 tag | 26 390 (1 pack) | 1,8 MB / 13,5 MB | format 0, extension, submodule, LFS ve symlink yok. 2010'dan beri geçmiş |

### Edinme yöntemi

Bu, pilotun tek ağ adımıydı: yalnızca `github.com` üzerinden, yalnızca bu üç repo.

- **Git:** güvenilir executable `C:\Program Files\Git\mingw64\bin\git.exe`; yazma yetkisi yalnızca SYSTEM ve Administrators'ta.
- **İzole yapılandırma:**
  - `GIT_CONFIG_NOSYSTEM=1`, boş global config, özel `HOME`;
  - `GIT_TERMINAL_PROMPT=0`, credential helper kapalı;
  - `--template=` ve `core.hooksPath=NUL` (hook yok);
  - `--no-recurse-submodules`, `GIT_LFS_SKIP_SMUDGE=1` ve LFS filtreleri boş;
  - `protocol.allow=never` + yalnızca `https`;
  - `core.symlinks=false`, `core.autocrlf=false`;
  - `transfer.fsckObjects=true` (alınan nesneler doğrulanıyor).
- **Flask istisnası:** İlk clone, 2010 dönemi commit'lerdeki `zeroPaddedFilemode` uyarısı yüzünden fsck'te reddedildi. Yalnızca bu mesaj `fetch.fsck.zeroPaddedFilemode=ignore` ile yok sayılarak yeniden clone edildi; diğer fsck kontrolleri açık kaldı.
- **Çalıştırılmayanlar:** Repo kodu, testleri, hook'ları ve kurulum betikleri hiç çalıştırılmadı. Bağımlılık indirilmedi.
- **Metadata komutları:** Clone'dan sonra salt-okunur `git` komutları çalıştırıldı (`rev-parse`, `rev-list`, `ls-files`, `count-objects`). Bunlar ilk bütünlük görüntüsünden önceydi.

## 3. Yöntem

### Laboratuvar: proje dışında, yalnızca bu pilota ait yerel bir klasör

| Klasör | İçerik |
|---|---|
| `env\` | Temiz venv. Doğrulanmış 0.1.0 wheel'i (sha256 `fef7f80b…24ea`) `--no-index --require-hashes` ile kuruldu. 64 paket dosyası wheel ile bayt düzeyinde aynı. Proje `.venv`'i (0.0.1) kullanılmadı. |
| `sources\` | Clone'lar |
| `reports\<repo>\<senaryo>\` | Auditor raporları |
| `measurements\` | Ölçümler ve loglar |
| `scripts\` | Pilot betikleri |
| `git-home\` | İzole git yapılandırması |

### Senaryolar (her repo için)

| Senaryo | Komut |
|---|---|
| s1 | `auditor scan <repo>` (ağsız, varsayılan) |
| s2 | `--scan-git-history` |
| s3 | `--fail-on high` |
| s4 | s1 çalıştırmasının `auditor report <RUN_ID>` ile `summary` ve `json` biçiminde gösterilmesi |

### Gözlem araçları

1. **Bütünlük görüntüsü.** Her taramadan önce ve sonra hedefteki tüm dosyalar (`.git` dahil) için SHA-256, boyut ve mtime alındı; link takip edilmedi. Klasör ve link listeleri de karşılaştırıldı. s4 için çalıştırma klasörü ayrıca görüntülendi.
2. **Süreç içi guard (`guard_run.py`, Python audit hook).** Auditor CLI bu guard altında çalıştı ve şunları kaydetti:
   - her alt süreç (executable ve cwd);
   - her DNS ve socket denemesi (loopback dışı **reddedildi**);
   - hedef altındaki her yazma, silme, yeniden adlandırma ve chmod girişimi;
   - hedeften her import, exec veya compile (**reddedildi**).

   Guard önce kendi kendini sınadı: yazma, DNS, bağlantı, import ve alt süreç girişimlerinin hepsi kaydedildi ve reddedildi.
3. **TCP izleyici.** Taramalar boyunca Auditor ortamına, araçlara ve Git'e ait süreçlerin loopback dışı TCP bağlantıları izlendi. Pencere 14:41:23Z–14:46:00Z, 524 yoklama (yaklaşık 0,5 sn aralık).
4. **Sızıntı kontrolü (`leak_check.py`).**
   - Secret değerleri yalnızca bellekte tutuldu; Gitleaks doğrudan çalıştırıldı ve raporu stdout'a yazdı.
   - Kaynaklar: çalışma ağacı (sabitlenmiş config ve varsayılan config) ve `gitleaks git --all`; leaky-repo'da ayrıca benchmark dosyalarındaki uzun token'lar.
   - Aranan yerler: tüm rapor dosyaları ve konsol çıktıları.
   - Aranan şeyler: tam değer, ≥20 karakterlik değerlerin orta 12 karakteri, yazar ve committer ad/e-postaları, mutlak yollar. Yalnızca sayılar yazdırıldı.
5. **Doğruluk.**
   - İlişkiler (`relations_check.py`): R1/R2 grupları doğrulandı, R2 için blob id yeniden hesaplandı. Kaçırılan grup arandı. Çalışma ağacındaki Gitleaks sonuçları doğrudan `gitleaks dir` ile konum bazında karşılaştırıldı.
   - Benchmark (`leaky_benchmark.py`): leaky-repo `secrets.csv` ile karşılaştırıldı.
   - Vulpy ve Flask bulguları kod okunarak elle sınıflandırıldı (yalnızca veri olarak okundu; hiçbir şey çalıştırılmadı).

### Gözlem araçlarının sınırları

- Guard yalnızca Auditor'ın kendi Python sürecini görüyor. Alt süreçlerin dosya erişimi bütünlük görüntüsüyle, ağ erişimi TCP izleyiciyle kapsandı.
- TCP izleyici yoklama yapıyor (yaklaşık 0,5 sn), bu yüzden çok kısa bağlantıları kaçırabilir. Pozitif kontrol yapılmadı, çünkü loopback dışı bir bağlantı izinsiz ağ erişimi olurdu.
- Bütünlük görüntüsü erişim zamanını (atime) izlemiyor.

## 4. Ölçüm tablosu

PARTIAL'ın tek nedeni bağımlılık alanı olduğunda (`NOT_PERMITTED`), bu kullanıcı kararıyla beklenen davranıştır; ürün hatası değildir.

| Repo / senaryo | Exit | Süre | Kapsam | Ruff | Semgrep | Gitleaks (çalışma ağacı) | pip-audit | Gitleaks (geçmiş) | CRIT | HIGH | MED | LOW | UNRATED | Geçmiş bulgusu | Analiz edilemeyen | Gate | `report.json` / `.md` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| vulpy s1 | 3 | 19,5 sn | PARTIAL (dependencies NOT_PERMITTED) | SUCCESS 57/57 | SUCCESS 57/57 | SUCCESS 113/113 | SKIPPED 0/1 | — | 0 | 0 | 62 | 61 | 0 | — | 0 | NOT_EVALUATED | 269 / 30 KB |
| vulpy s2 | 3 | 18,3 sn | PARTIAL (+ secrets_history PARTIAL) | SUCCESS | SUCCESS | SUCCESS | SKIPPED | SUCCESS 313/319 (blob 255/261, mesaj 58/58), 1,5 sn | 0 | 0 | 66 | 61 | 0 | 4 | 6 nesne: 5 SQLite `TOOL_ERROR`, 1 nesne >10 MiB `SIZE_LIMIT` | NOT_EVALUATED | 296 / 34 KB |
| vulpy s3 | **3** | 19,2 sn | PARTIAL | SUCCESS | SUCCESS | SUCCESS | SKIPPED | — | 0 | 0 | 62 | 61 | 0 | — | 0 | **PASSED** (0 ≥ high) | 269 / 30 KB |
| leaky-repo s1 | 3 | 13,9 sn | PARTIAL (**secrets_working_tree PARTIAL**; dependencies NOT_APPLICABLE) | SUCCESS 2/2 | SUCCESS 2/2 | SUCCESS 58/60 | SKIPPED (manifest yok) | — | 2 | 2 | 20 | 4 | 0 | — | 2 dosya (`cert9.db`, `key4.db`) `TOOL_ERROR` | NOT_EVALUATED | 105 / 17 KB |
| leaky-repo s2 | 3 | 13,1 sn | PARTIAL | SUCCESS | SUCCESS | SUCCESS 58/60 | SKIPPED | SUCCESS 153/155 (blob 127/129, mesaj 26/26), 2,0 sn | 4 | 6 | 48 | 4 | 0 | 34 (CRIT 2, HIGH 4, MED 28) | 2 dosya + 2 nesne (aynı NSS db'leri) | NOT_EVALUATED | 199 / 42 KB |
| leaky-repo s3 | **4** | 11,0 sn | PARTIAL | SUCCESS | SUCCESS | SUCCESS | SKIPPED | — | 2 | 2 | 20 | 4 | 0 | — | 2 dosya | **FAILED** (4 ≥ high) | 106 / 17 KB |
| flask s1 | 3 | 30,6 sn | PARTIAL (dependencies NOT_PERMITTED, 6 manifest) | SUCCESS 83/83 | SUCCESS 83/83 (0 bulgu) | SUCCESS 236/236 | SKIPPED 0/6 | — | 0 | 2 | 28 | 21 | 0 | — | 0 | NOT_EVALUATED | 272 / 19 KB |
| flask s2 | 3 | 59,0 sn | PARTIAL (+ secrets_history PARTIAL) | SUCCESS | SUCCESS | SUCCESS | SKIPPED | SUCCESS 14 918/14 921 (blob 9315/9318, mesaj 5603/5603), 27,2 sn | 0 | 2 | 252 | 21 | 0 | 224 (hepsi MED `generic-api-key`) | 3 nesne `SKIPPED_BY_TOOL` (2 PDF, 1 `.egg`) | NOT_EVALUATED | **752** / 88 KB |
| flask s3 | **4** | 30,4 sn | PARTIAL | SUCCESS | SUCCESS | SUCCESS | SKIPPED | — | 0 | 2 | 28 | 21 | 0 | — | 0 | **FAILED** (2: S102, S307) | 272 / 19 KB |

### Ortak sonuçlar

- **Diğer rapor dosyaları:** Her çalıştırmada 5 dosya var (`report.json`, `report.md`, `findings.json`, `inventory.json`, `SHA256SUMS.json`). Ek boyutlar: `findings.json` 72–586 KB, `inventory.json` 18–67 KB.
- **`auditor report` (s4):** 3 repoda da exit 0; süre 0,3–0,4 sn.
  - Yeni alt süreç ve ağ denemesi yok; yeni çalıştırma klasörü oluşmadı; çalıştırma klasörü bayt düzeyinde aynı kaldı.
  - `--format json` çıktısı `report.json` ile birebir aynı.
- **Durum ayrımı:**
  - **PARTIAL:** 9/9 tarama. Nedenleri yukarıda; hepsi doğru ve açıklanmış.
  - **TIMED_OUT, ERROR, CLEANUP_FAILED:** 0.
- **Operasyonel uyarı `STALE_WORKSPACES_FOUND`:** Her taramada çıktı. Nedeni, `%TEMP%\aca` altındaki 82 eski klasörden 42'si. Beklenen davranış (D-042); hiçbiri silinmedi.
- **İlişki grupları:**
  - vulpy: R1 10 (s1, s3), R1 10 + R2 1 (s2);
  - leaky-repo: R2 22 (s2);
  - flask: R2 6 (s2);
  - R3 hiçbir senaryoda oluşmadı (OSV sorgusu yok; beklenen).

### Değişmezler

| Değişmez | Sonuç |
|---|---|
| Hedef bütünlüğü | Her repo için ilk ve son görüntü aynı. Toplam 9 tarama + 6 report komutu boyunca değişiklik yok. Sızıntı kontrolündeki doğrudan Gitleaks çalıştırmalarından sonra da aynı kaldı. |
| Guard | Ağ denemesi 0, hedefe yazma 0, hedef kodu import/exec/compile 0, cwd'si hedefte olan alt süreç 0, loopback 0. |
| Alt süreç executable'ları | Yalnızca şu dördü: `C:\Program Files\Git\mingw64\bin\git.exe`, `env\Scripts\ruff.exe`, `ai-code-auditor\tools\gitleaks\8.30.1\gitleaks.exe`, `ai-code-auditor\tools\semgrep\Scripts\semgrep.exe` |
| TCP izleyici | 0 bağlantı (524 yoklama) |
| Geçici dosyalar | Auditor'ın kendi geçici klasörü boş. Yeni `r-*` çalışma klasörü yok. Sistem geçici klasöründeki eski deney kalıntıları (82 klasör, 1075 girdi) değişmedi. |
| Ana proje | HEAD `0ecc262`, git status ve nesne sayısı değişmedi (bu belge dışında) |

### Sızıntı kontrolü

| Repo | Doğrudan Gitleaks bulgusu (pinned / default / git) | Farklı değer | Aranan dosya | Değer / orta parça eşleşmesi | Benchmark token'ı (aranan / eşleşen) | Yazar ve e-posta | Mutlak yol (rapor dosyaları) |
|---|---|---|---|---|---|---|---|
| vulpy | 1 / 1 / 4 | 1 | 23 | 0 / 0 | — | 0 * | 0 |
| leaky-repo | 22 / 22 / 26 | 16 | 23 | 0 / 0 | 182 / 0 | 0 | 0 |
| flask | 6 / 6 / 12 | 2 | 23 | 0 / 0 | — | 0 * | 0 (1741 ad/e-posta arandı) |

\* İlk eşleşmeler incelendi ve ikisi de sözlük kelimesi çıktı. Vulpy'de bir yazar adı olan "root", rapordaki "root cause" ifadesinde geçiyor. Flask'ta bir yazar adı olan "unknown", "Version: unknown" ifadesinde geçiyor. Gerçek kişi verisi yok.

## 5. Doğruluk değerlendirmesi

Sınıflar:
- **Gerçek bulgu:** Kuralın iddia ettiği güvenlik açısından ilgili desen kodda gerçekten var.
- **Yanlış pozitif (YP):** Desen eşleşti ama bağlamda güvenlik sorunu değil.
- **Belirsiz:** Bağlama veya güven varsayımına bağlı.

### 5.1 Vulpy (bilerek zafiyetli uygulama)

Kapsam kuralı: Recall yalnızca mevcut kuralların (Ruff S, 14 Semgrep kuralı, Gitleaks) yakalayabileceği sınıflardaki, kod okunarak doğrulanmış açıklar için ölçüldü. Kapsam, kasıtlı zafiyetli sürüm olan `bad/` ile sınırlı. Desteklenmeyen sınıflar §6'da.

**Doğrulanmış, desteklenen açıklar (`bad/`):** 9/9 tespit edildi.

| # | Açık | Konum | Tespit | Raporlanan önem |
|---|---|---|---|---|
| 1 | SQL injection (login; form → `str.format` → `execute`) — kimlik doğrulama atlatma | `bad/libuser.py:12` | Semgrep `formatted-sql-query` + Ruff S608 (R1 grubu) | MEDIUM |
| 2 | SQL injection (kullanıcı oluşturma) | `bad/libuser.py:25` | Semgrep + S608 (R1) | MEDIUM |
| 3 | SQL injection (parola değiştirme; kullanıcı adı sahte çerezden) | `bad/libuser.py:53` | Semgrep + S608 (R1) | MEDIUM |
| 4 | Flask `debug=True` (Werkzeug debugger) | `bad/vulpy.py:55` | S201 + Semgrep (R1) | MEDIUM |
| 5 | Flask `debug=True` | `bad/vulpy-ssl.py:29` | S201 + Semgrep (R1) | MEDIUM |
| 6 | Sabit, zayıf `SECRET_KEY` | `bad/vulpy.py:16` | Ruff S105 (Gitleaks yok: düşük entropi) | MEDIUM |
| 7 | Sabit `SECRET_KEY` | `bad/vulpy-ssl.py:13` | Ruff S105 | MEDIUM |
| 8 | API anahtarlarının paylaşımlı `/tmp` dosya adlarında tutulması | `bad/libapi.py:16,20,33` | Ruff S108 ×3 | MEDIUM |
| 9 | API anahtarının paylaşımlı `/tmp` dosyasına yazılması | `bad/api_post.py:6` | Ruff S108 | MEDIUM |

- **Yanlış negatif (desteklenen sınıflarda):** 0.
- **Taint kuralları:** `tainted-sql-query` (ERROR) hiç tetiklenmedi, çünkü kaynak (`request.form`) ile sink farklı fonksiyonlarda (`mod_user` → `libuser`). Fonksiyonlar arası taint'in desteklenmediği zaten belgelenmişti (Semgrep CE).
- **Örneklem küçük:** 9 açık. Bu sayı genelleştirilemez.

**Hassasiyet: 59 güvenlik bulgusu** (Ruff S 48, Semgrep 10, Gitleaks 1; R1 ile 49 konum).

| Bölüm | Bulgu | Gerçek | YP | Belirsiz | YP / belirsiz ayrıntısı |
|---|---|---|---|---|---|
| `bad/` | 27 | 21 | 6 | 0 | S608 + Semgrep `db.py:19`, `db_init.py:20` (4 bulgu; sabit tohum verisi, istismar edilemez); S603 `brute.py:21` (kasıtlı brute-force aracı, shell yok); S110 `libsession.py:21` |
| `good/` | 15 | 13 | 1 | 1 | YP: S110 `good/libsession.py:22`. Belirsiz: S108 `good/cutpasswd.py:3` (`/tmp`'den kelime listesi okuma) |
| `utils/` | 17 | 17 | 0 | 0 | — (S108 ×15: özel anahtarlar `/tmp`'ye yazılıp okunuyor; S113 ×2) |
| **Toplam** | **59** | **51 (%86)** | **7** | **1** | |

Notlar:
- `good/` hâlâ gerçek sorunlar içeriyor; bunlar araç hatası değil, doğru bulgular:
  - `good/libuser.py:61` SQL injection;
  - `good/libsession.py:9` sabit Fernet anahtarı (Gitleaks);
  - `good/libapi.py:10` sabit secret (S105);
  - `debug=True`.
- Gerçek bulguların çoğu düşük riskli: S113 timeout eksikliği, `/tmp` kullanımı.

**Önem kalibrasyonu:** Vulpy'deki istismar edilebilir 3 SQL injection'ın hepsi MEDIUM. Hiçbir bulgu HIGH değil, bu yüzden `--fail-on high` kapısı **geçiyor** (exit 3, yalnızca bağımlılık PARTIAL'ı yüzünden). Bkz. P1.

### 5.2 leaky-repo (sahte secret benchmark'ı)

- **Kıyas verisi:** Repo'nun kendi `.leaky-meta/secrets.csv` dosyası: 44 dosya; dosya başına risk satırı ve bilgi satırı sayısı.
- **Eşleştirme yöntemi:** Benchmark satır numarası vermediği için dosya başına ve farklı satır sayısıyla eşleştirildi. Satır rakamı bu yüzden bir **üst sınır**: bulunan bir satır risk satırı değil, bilgi satırı da olabilir.
- **Eski Gitleaks sonuçları karşılaştırılamaz:** Repo'daki `GITLEAKS.md` sonucu (127/175), eski bir Gitleaks sürümü ve özel bir config ile, bilgi satırları da sayılarak üretilmiş.

| Metrik | Değer |
|---|---|
| Risk içeren dosya | 42 |
| En az bir bulgusu olan risk dosyası | **14 / 42 (%33)** |
| Risk satırı (üst sınır eşleşme) | **≤ 22 / 96 (≤ %23)** |
| Yalnızca bilgi içeren dosyalarda bulgu (`id_rsa.pub`, `high-entropy-misc.txt`) | 0 (dosya düzeyinde YP yok) |
| Risk sayısından fazla bulunan satır | 1 (`cloud/.s3cfg`: 2 satır / 1 risk; muhtemelen bilgi satırı) |
| Benchmark dışında bulgu | 1 (`.leaky-meta/benchmark.py` Ruff S603; benchmark aracının kendisi, secret değil) |
| Analiz edilemeyen | 2 Firefox NSS veritabanı (`cert9.db`, `key4.db`): `TOOL_ERROR` → PARTIAL. Benchmark bu dosyaları saymıyor |
| Adaptör doğruluğu | Auditor'ın 22 çalışma ağacı bulgusu, doğrudan `gitleaks dir` (sabitlenmiş config) ile (yol, satır, kural) düzeyinde **birebir aynı** |
| Geçmiş | 34 bulgu (`gitleaks git`: 26); (yol, kural) çiftleri 15 = 15. Fark, nesne başına raporlamadan geliyor |

**Bulunanlar:**
- özel anahtarlar (`.ssh/id_rsa`, `misc-keys/cert-key.pem`; CRITICAL);
- Slack ve Mailchimp token'ları (HIGH);
- AWS, Heroku, Tugboat, Docker, npm ve hub token'ları ile Rails `secrets.yml` (`generic-api-key`, MEDIUM);
- Django `SECRET_KEY` (yalnızca Ruff S105).

**Kaçırılanlar (Gitleaks varsayılan kural setinin sınırı):**
- `db/dump.sql` (10 bcrypt hash), `etc/shadow`, `.htpasswd`, `proftpdpasswd`: parola hash'leri;
- `wp-config.php` (9), `config.php`, `web/var/www/.env` (6): düşük entropili parolalar ve PHP `define`;
- `.mozilla/firefox/logins.json` (8): şifrelenmiş kimlik bilgileri;
- `.netrc`, `.git-credentials`, `.pgpass`, `.esmtprc`, `ventrilo_srv.ini`: düz parola dosyaları;
- FileZilla, DBeaver, JetBrains, VS Code / Atom / Sublime SFTP config'leri, robomongo, mongoid;
- PuTTY `.ppk`, Rails `master.key`, Salesforce JS.

### 5.3 Flask (gerçek dünya; yanlış pozitif, performans, kapsam)

**Örneklem:** Güvenlik kategorisindeki **34 bulgunun tamamı** değerlendirildi; istenen en az 20'nin üstünde. Kalan 17 bulgu bakım ve stil türünden: C901, F401, E402, B018.

| Kural | Bulgu | Gerçek | YP | Belirsiz | Gerekçe |
|---|---|---|---|---|---|
| Gitleaks `generic-api-key` | 6 | 0 | 6 | 0 | `docs/config.rst` (5), `docs/tutorial/deploy.rst` (1): dokümantasyondaki örnek `SECRET_KEY` değerleri |
| S105 / S106 / S107 (`tests/`) | 9 | 0 | 9 | 0 | Test fixture değerleri |
| S106 `examples/tutorial/flaskr/__init__.py:11` | 1 | 1 | 0 | 0 | Örnek uygulamada sabit, kısa bir varsayılan secret yer tutucusu (yorumda "override edilmeli" yazıyor). Düşük risk |
| S101 `assert` (`src/`) | 5 | 0 | 5 | 0 | Geliştirici tutarlılık kontrolleri, güvenlik denetimi değil |
| S102 `config.py:209` (`from_pyfile` exec) | 1 | 1 | 0 | 0 | Gerçek kod çalıştırma noktası; tasarım gereği, girdi güvenilir config dosyası |
| S307 `cli.py:1022` (`flask shell` PYTHONSTARTUP eval) | 1 | 1 | 0 | 0 | Gerçek nokta; tasarım gereği, girdi kullanıcının kendi startup dosyası |
| S110 | 7 | 0 | 7 | 0 | `config.py:163` (bilinçli string'e geri dönüş) ve testler |
| S324 `sessions.py:281` (`hashlib.sha1`) | 1 | 0 | 1 | 0 | itsdangerous HMAC-SHA1 imzası; HMAC-SHA1 kırık değil |
| S704 `json/tag.py:188` (`Markup(value)`) | 1 | 0 | 0 | 1 | İmzalı oturum verisinden Markup üretiliyor; güvenlik, secret key'in gizli kalmasına bağlı |
| S704 (`tests/`) | 2 | 0 | 2 | 0 | Escape davranışını sınayan testler |
| **Toplam** | **34** | **3 (%9)** | **30** | **1** | **YP'lerin 20'si `tests/`, 6'sı `docs/` altında** |

Diğer gözlemler:
- **Semgrep:** Flask'ta 0 bulgu (taint kaynağı yok). Beklenen ve doğru.
- **Performans:** 236 dosya / 5603 commit / 26 390 nesne için tam geçmiş taraması 59 sn sürdü (Gitleaks-history 27 sn). 900 sn sınırının çok altında.
- **Geçmiş gürültüsü:** 224 geçmiş bulgusunun hepsi `docs/config.rst` (220) ve `docs/tutorial/deploy.rst` (4) altında; en fazla 2 farklı değer. `gitleaks git` aynı içerik için 12 bulgu veriyor; (yol, kural) çiftleri aynı (2 = 2). Fark şuradan: Auditor değeri içeren **her blob sürümünü**, `gitleaks git` yalnızca değerin **eklendiği diff'i** raporluyor. Bkz. P2.

### 5.4 R1–R3 ilişkilendirme

| İlişki | Grup | Doğrulama | Sonuç |
|---|---|---|---|
| R1 `same_location` | 10 (vulpy) | Her grupta aynı yol ve satır, farklı araçlar, hepsi security kategorisinde. Gruplanmamış aynı satırlı güvenlik çifti: 0 | **Doğru ve anlamlı.** S608 ↔ `formatted-sql-query` (6) ve S201 ↔ `flask-debug-enabled` (4) aynı açığı iki araçla doğruluyor |
| R2 `same_content_in_history` | 1 / 22 / 6 | Her üye için çalışma ağacı dosyasının git blob id'si yeniden hesaplandı; aynı blob id, satır, kural ve geçmiş yolu tuttu. Kaçırılan R2: 0 | **Doğru.** "Bu secret geçmişte de aynı içerikle var" bilgisini veriyor. Flask'ta 224 bulgunun yalnızca 6'sı gruplandı: R2 tasarım gereği (blob ve satır aynı olmalı) eski sürümleri bağlamıyor |
| R3 `same_vulnerability` | 0 | OSV sorgusu yok | Bu pilotta sınanmadı (beklenen) |

## 6. Kapsam boşlukları (yanlış negatif metriğine katılmadı)

| Sınıf | Örnek (repo: konum) | Neden yakalanmıyor |
|---|---|---|
| Şablonlarda XSS (`\|safe`) | vulpy: `bad/templates/posts.view.html:23`, `messages.html:8` (stored/reflected XSS) | Semgrep kurallarımız yalnızca Python dosyalarını tarıyor; Jinja şablonları analiz edilmiyor |
| İmzasız oturum çerezi / oturum sahteciliği | vulpy: `bad/libsession.py` (base64 JSON, imza yok) | Kimlik doğrulama ve iş mantığı kapsam dışı |
| Glob/joker karakter enjeksiyonu ile kimlik doğrulama atlatma | vulpy: `bad/libapi.py:33` (`X-APIKEY: *`) | Path traversal kuralının sink'leri `Path.glob`'u modellemiyor |
| Zayıf rastgelelik | vulpy: `bad/libapi.py:14` (`random.getrandbits`) | Ruff S311 `getrandbits`'i kapsamıyor (ayrı snippet ile doğrulandı) |
| Düz metin parola saklama, SQL trace ile parola loglama | vulpy: `libuser.create`, `set_trace_callback(print)` | Mantık ve akış analizi gerekiyor |
| Veri yapılarında sabit kimlik bilgisi | vulpy: `bad/db_init.py` (tuple listesi) | S105/S106 yalnızca parola benzeri isimlere atama ve argüman arıyor |
| CSRF, brute-force koruması, parola karmaşıklığı, MFA mantığı | vulpy | Kapsam dışı |
| Düşük entropili parolalar, hash'ler, config dosyalarındaki kimlik bilgileri, şifrelenmiş tarayıcı parolaları | leaky-repo (§5.2) | Gitleaks varsayılan kural seti (adaptör birebir aynı sonucu veriyor) |
| İkili veritabanları (SQLite, NSS) | vulpy geçmişi (5), leaky-repo (2 + 2) | Gitleaks içeriği okumayı doğrulamıyor → `TOOL_ERROR` → PARTIAL (doğru ve güvenli tarafta) |
| Arşiv/PDF/egg | flask geçmişi (3) | `SKIPPED_BY_TOOL` → PARTIAL |
| 10 MiB üstü nesne | vulpy geçmişi (`good/utils/sys`) | `SIZE_LIMIT` → PARTIAL |
| Bağımlılık zafiyetleri | vulpy (1 manifest), flask (6 manifest) | Bu pilotta OSV izni yok → `NOT_PERMITTED` (beklenen) |

## 7. Ürün bulguları (bu aşamada düzeltilmedi)

Güvenlik hatası yok. Hepsi doğruluk, gürültü veya kullanılabilirlik konusu. Her biri kaydedilen raporlarla tekrarlanabilir.

| # | Tür | Bulgu | Tekrarlama | Etki |
|---|---|---|---|---|
| P1 | Önem kalibrasyonu (yüksek öncelik) | Desen tabanlı SQL injection (Semgrep WARNING, Ruff S608) ve `debug=True` MEDIUM. Taint kuralı ERROR → HIGH, ama fonksiyonlar arası akışta tetiklenmiyor. Sonuç: zafiyetli uygulama `--fail-on high`'dan geçiyor | `auditor scan vulpy --fail-on high` → exit 3, gate PASSED; `bad/` altındaki 5 SQL bulgusunun (3'ü istismar edilebilir) hepsi MEDIUM | CI kapısı "high" ile en önemli web açığını kaçırıyor; kullanıcı yanlış güven duyabilir |
| P2 | Gürültü | Geçmiş taraması aynı değeri içeren her blob sürümü için ayrı bulgu üretiyor. Flask'ta en fazla 2 değer için 224 bulgu; R2 yalnızca çalışma ağacındaki aynı blob'u bağlıyor | `auditor scan flask --scan-git-history` | Rapor şişiyor (`report.json` 752 KB); gerçek yeni secret'lar gözden kaçabilir |
| P3 | Gürültü / bağlam | Test ve dokümantasyon yollarındaki bulgular gate'te ve özette aynı ağırlıkta sayılıyor (`test-path` etiketi var ama önemi düşürmüyor). S101 `src/` altında güvenlik bulgusu sayılıyor | Flask s1: 34 güvenlik bulgusunun 30'u YP | Gerçek dünya repolarında hassasiyet %9 |
| P4 | Gate kullanılabilirliği | Tasarım gereği riskli API'ler (S102/S307) gate'i kalıcı olarak düşürüyor. Bulguyu gizlemeden kabul edilmiş bir riski işaretlemenin yolu (hedef dışında, kullanıcı onaylı baseline) yok | `auditor scan flask --fail-on high` → exit 4 | CI'da "high" kapısı Flask gibi projelerde sürekli kırmızı |
| P5 | Raporlama kesinliği | İkili SQLite/NSS veritabanları `TOOL_ERROR` ("input not fully consumed" / "end marker"), PDF ve egg ise `SKIPPED_BY_TOOL` olarak etiketleniyor. Kapsam etkisi doğru (PARTIAL), ama "araç hatası" etiketi yanıltıcı olabilir. Kök neden (Gitleaks'in ikili içerik davranışı) doğrulanmadı | vulpy s2, leaky-repo s1 ve s2 | Kullanıcı gerçek bir araç arızası sanabilir |
| P6 | Kullanılabilirlik | Ağ izni yokken konsol `Pip-audit: SKIPPED (version unknown)` diyor; araç kurulu ve `doctor` sürümü (2.10.1) gösteriyor | Her ağsız tarama | Küçük; kafa karıştırıcı |
| P7 | Operasyonel gürültü | `STALE_WORKSPACES_FOUND` uyarısı her taramada 42 eski klasör için tekrarlanıyor (bilinçli politika, D-042) | Her tarama | Elle temizlik kararı bekliyor; uyarı yorgunluğu riski |
| P8 | Yeniden üretilebilir build | `src/auditor/rules/semgrep/MANIFEST.json` git'te LF (`eol=lf`), ama çalışma ağacında ve test edilen wheel'de CRLF. Temiz bir clone'dan üretilen wheel farklı hash verir. Manifest JSON olarak okunduğu için işlevsel etki yok; kural dosyalarının hash'leri iki durumda da aynı | `git ls-files --eol src/auditor/rules/semgrep/MANIFEST.json` → `i/lf w/crlf` | Wheel hash'i kaynak checkout'una bağlı |

## 8. Önerilen sonraki iyileştirmeler

Önerilerdir; her biri ayrı plan ve onay gerektirir.

1. **P1, önem politikası:**
   - SQL injection ve `debug=True` için önem eşlemesini gözden geçirmek. Örneğin desen tabanlı SQL için HIGH, ya da R1 ile iki araç aynı açığı doğruladığında güven/öncelik bilgisi.
   - README'de "`--fail-on high`, desen tabanlı SQL injection'ı yakalamaz" uyarısı; CI için `--fail-on medium` önerisi.
2. **P2, geçmiş bulgularının tekilleştirilmesi:** Aynı kural ve aynı değer için (değer saklanmadan; bellekte tuzlu hash ile) tek bir "geçmiş grubu" ilişkisi. Raporda ilk ve son görüldüğü commit.
3. **P3, bağlama duyarlı sayım:** `test-path` / `docs-path` bulgularını özette ayrı göstermek. Gate için açık bir seçenek: `--gate-scope production`. Bulgular raporda kalır, gizlenmez.
4. **P4, kullanıcı onaylı baseline:** Hedef repoda değil, kullanıcının kendi dizininde duran, gerekçe ve imzalı karma içeren bir kabul dosyası. Gate bunu yalnızca ayrı bir sayımla uygular; bulgu raporda görünmeye devam eder.
5. **Secret kapsamı:**
   - Gitleaks'e ek kural paketi (hedef config'ten değil, auditor'ın sürümlü kurallarından): `.netrc`, `.git-credentials`, URL içi kimlik bilgisi, PHP `define`, `.env` `*_PASSWORD`, bcrypt/shadow hash'leri.
   - Ölçüm aynı leaky-repo benchmark'ıyla tekrarlanmalı.
6. **Şablon XSS:** Jinja `|safe` / `Markup` için şablon dosyası analizi (Semgrep generic veya kendi kuralımız) ayrı bir aşama olarak.
7. **P5/P6 rapor düzeltmeleri:** İkili içerik için ayrı bir `BINARY_NOT_SCANNED` nedeni; atlanan pip-audit için kurulu sürümün gösterilmesi.
8. **P8:** `MANIFEST.json`'ın çalışma ağacında LF'e normalize edilmesi (`git add --renormalize`) ve build öncesi kontrol.
9. **İkinci pilot (ayrı onayla):**
   - PyGoat, DVPWA, Requests, Django (performans, 900 sn sınırı);
   - isteğe bağlı OSV ile R3 ve pip-audit doğrulaması (yalnızca onaylı paket listesi).

## 9. Laboratuvar ve veri durumu

- Laboratuvar klasörü **silinmedi** (kullanıcı kararı bekleniyor).
  - Clone'lar, kamuya açık sahte secret'lar (leaky-repo) ve kasıtlı zafiyetli kod içeriyor.
  - Rapor ve ölçüm dosyalarında secret değeri yok (§4).
- Kaynak: `sources\` (3 clone).
- Raporlar: `reports\` (9 çalıştırma klasörü).
- Ölçümler: `measurements\`
  - `acquisition*.json`, `metrics.json`, `tcp_monitor.log`, `temp_before/after.json`, `project_before.txt`;
  - repo başına: `scenarios.json`, `leak_check.json`, `relations_check.json`, `benchmark.json` (leaky-repo), guard logları, konsol çıktıları ve bütünlük görüntüleri.
- Betikler: `scripts\`: `acquire.py`, `guard_run.py`, `snapshot.py`, `tcp_monitor.ps1`, `run_pilot.py`, `leak_check.py`, `metrics.py`, `relations_check.py`, `leaky_benchmark.py`, `context.py`, `author_hit.py`.
- Pilot dışı etkiler:
  - geçici çalışma alanında iki küçük deneme klasörü: `glstdout_probe` (Gitleaks stdout denemesi) ve `s311probe` (Ruff S311 denemesi), ikisi de kendi yazdığım dosyalar;
  - guard öz-sınama hedefi oluşturulup silindi.
- Proje deposu: yalnızca bu belge eklendi (commit'lenmedi). 82 eski klasör, önceki laboratuvar verileri ve git geçmişi değişmedi.

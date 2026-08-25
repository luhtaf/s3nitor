# s3nitor — roadmap: apa dikerjakan, apa ditulis

Dokumen ini duduk **di atas** rencana implementasi di
`~/.claude/plans/refactored-watching-axolotl.md`. Rencana itu menjelaskan *bagaimana*
pipeline dibangun (Fase 1–5, interface, skema, config). Yang ini menjelaskan *kapan*
tiap bagian dikerjakan, dan artikel mana yang baru bisa ditulis setelahnya.

Aturan yang dipakai untuk mengurutkan: **satu artikel tidak boleh dijadwalkan sebelum
pekerjaan yang menghasilkan angkanya selesai.** Menulis lebih dulu memaksa mengarang.

---

## Posisi sekarang (2026-08-24)

| Hal | Status |
|---|---|
| Branch `feat/staged-pipeline-foundations` | 7 commit, working tree bersih, belum di-push |
| Fase 0 — validasi infra | **Selesai.** MinIO+Redis, MinIO+Kafka, SeaweedFS+Kafka lulus |
| Fixture payload | Tersimpan di `test/fixtures/` — jadi masukan unit test decoder |
| Dependency & CVE | trivy 0, govulncheck 0, toolchain dipatok `go1.25.13` |
| CI | build, vet, tidy, smoke test cgo, govulncheck |
| Artikel A | Draft selesai, belum terbit |
| Pipeline (Fase 1–5) | **Belum dibangun** |
| Harness benchmark | Belum ada |
| Dashboard | Belum ada |

---

## Tiga jalur dan ketergantungannya

```
KODE                    EKSPERIMEN              TULISAN

M1 Fondasi
   │
M2 Pipeline + metrik ──► M3 Harness sizing ────► Artikel B
   │                                             (sizing & benchmark)
M4 Lane + intel
   │
M5 Event source
   │
M6 Dashboard + demo ─────────────────────────────► Artikel C
                                                   (demo publik)

Artikel A ─── tidak bergantung apa pun ─────────► siap terbit sekarang
```

---

## Milestone

### M1 — Fondasi
Isi Fase 1 pada plan: `hashing.Hasher`, interface `Scanner` baru
(`Scan(ctx, in) (Result, error)`), skema `FileRecord` + `ScanTask`, connection pool DB
dan pragma SQLite.

Worker loop lama tetap dipakai dan disesuaikan — **tidak ada perubahan perilaku.**

**Selesai bila:** binari jalan seperti sebelumnya; scanner sudah jadi fungsi murni;
ada unit test pertama di repo (sekarang nol); `go test ./...` di CI mulai berarti.

**Membuka:** atribusi metrik per-scanner. Selama scanner masih memutasi satu
`ScanContext` bersama, biaya CPU tidak bisa dipisahkan per scanner — dan itu justru
angka yang dibutuhkan Artikel B.

### M2 — Pipeline + metrik
Isi Fase 2: empat stage, limiter statik, byte budget, publish ter-batch.

**Ditarik maju dari Fase 5: exporter Prometheus.** Alasannya praktis — Artikel B
adalah artikel pengukuran, dan tanpa instrumentasi tidak ada yang bisa diukur selain
angka gelondongan dari luar. Versi ramping saja: counter dan histogram per stage,
kedalaman antrian, byte in-flight, nilai limit sekarang.

**Selesai bila:** byte budget terbukti membatasi RSS pada objek besar; `/metrics`
menyajikan angka per stage; worker loop lama dihapus.

**Membuka:** Artikel B.

### M3 — Harness sizing
Bukan kode aplikasi — skrip eksperimen.

Yang harus ada:
- **Definisi workload sebagai warga kelas satu.** Distribusi ukuran objek, laju
  kedatangan, scanner mana yang aktif. Tanpa ini angka tidak bisa direproduksi.
- Sweep: worker/limit × ukuran objek.
- Pencatat metrik. **Wajib RSS container / `memory.current` cgroup**, bukan
  `runtime.MemStats` — driver SQLite itu cgo, alokasinya di luar heap Go, jadi
  `MemStats` bisa terlihat sehat sementara pod kena OOM kill.
- Keluaran berupa tabel yang bisa langsung masuk artikel.

Eksperimen yang dijalankan:

| Diukur | Cara | Untuk apa |
|---|---|---|
| Baseline idle | RSS, 0 objek, rules ter-load | lantai `requests.memory` |
| Biaya rules | RSS sebelum/sesudah load N IOC + M YARA | IOC map tumbuh linier |
| Memori vs **ukuran** objek | worker tetap, 10 KB vs 100 MB | bukti klaim byte-budget |
| Memori vs **jumlah** worker | sweep worker, objek seragam | knob mana yang menyetir RAM |
| Plateau CPU | sweep, catat throughput | titik datar = `limits.cpu` |
| Latensi deteksi | upload → temuan di sink | angka pembanding event vs cron |
| Biaya idle | konsumsi saat bucket diam | cron tetap nge-list; event nol |

**Selesai bila:** satu perintah menghasilkan tabel yang sama pada dua kali jalan.

### M4 — Lane per scanner + intel
Isi Fase 3: antrian + limiter per scanner, `PendingStore`, spill/retry,
`internal/scanner/intel` (OTX dipindah ke sana, VirusTotal ditambahkan).

VirusTotal jadi bukti jalur spill benar-benar bekerja, karena kuotanya paling ketat.

**Selesai bila:** dengan `VT_RATE_PER_MIN=4`, ioc/yara tetap selesai dalam hitungan
detik sementara task VT menyicil tanpa menahan apa pun.

### M5 — Event source
Isi Fase 4: `SOURCE_MODE=event`, transport Redis/Kafka, decoder MinIO, deteksi format
otomatis. Diuji lawan fixture Fase 0 — decoder diuji terhadap byte asli.

**Selesai bila:** event yang sama dikirim dua kali menghasilkan jumlah dokumen tetap.

### M6 — Dashboard + bucket demo
- Bucket demo berisi EICAR, file bersih yang hash-nya sengaja dimasukkan ke daftar IOC,
  file bersih yang cocok dengan rule YARA buatan sendiri, beberapa file benar-benar
  bersih, dan satu file besar.
- **Tidak pernah ada malware asli di bucket publik.**
- Dashboard publik **hanya membaca** hasil dari sink. Tombol menjalankan scan hanya ada
  di versi self-host.
- **Tidak ada intake kredensial S3.** Yang mau memindai bucket sendiri memakai
  `docker run` atau `docker-compose` yang menyalakan MinIO ter-seed.
- Kode dashboard open source.

**Membuka:** Artikel C.

---

## Rencana tulisan

### Artikel A — "One worker pool was the wrong shape"
**Status: draft selesai, tidak bergantung apa pun, siap terbit.**

Berdiri sendiri (bukan bagian seri). Isi: review concurrency, batas stage berdasarkan
resource, block-vs-spill, empat asumsi wire format yang terbantah, reachability scan.

Sisa pekerjaan: dua diagram SVG diekspor ke PNG, subtitle dipisah ke field Medium,
dua penanda gambar diisi.

Jujur menyatakan pipeline belum dibangun — itu harus tetap begitu.

### Artikel B — sizing dan benchmark
**Butuh M2 + M3.**

Sudut pandangnya **bukan** lomba benchmark storage. Membandingkan MinIO lawan SeaweedFS
di cluster satu node mengukur disk dan network sendiri, bukan produknya — dan itu bahan
empuk untuk dibantah.

Sudut yang dipakai: **cara menurunkan angka `requests` dan `limits` dari beban kerja
nyata.** Storage dan MQ muncul sebagai karakteristik integrasi, bukan peserta lomba.

Kerangka:
1. Definisi workload — ukuran objek, laju, campuran scanner
2. Baseline idle dan biaya rules
3. Jumlah worker lawan ukuran objek — knob mana yang sebenarnya menyetir RAM
4. Menurunkan `requests`/`limits` dari kurva itu
5. Before/after: worker pool lama lawan staged pipeline
6. Event lawan cron — latensi deteksi dan biaya diam
7. Karakteristik integrasi per storage/MQ (bukan perbandingan performa)

Klaim yang diuji, bukan diargumentasikan: worker count tetap, objek 10 KB lawan 100 MB
→ RSS berbeda jauh. Itu membuktikan atau membantah desain byte-budget.

### Artikel C — demo publik
**Butuh M6.**

Isi: apa yang dibangun, kenapa dashboard tidak menerima kredensial, cara menjalankan
sendiri, apa yang terlihat di output.

---

## Koreksi urutan dibanding rencana awal

1. **Exporter Prometheus pindah dari Fase 5 ke M2.** Artikel B adalah artikel
   pengukuran; instrumentasi adalah prasyaratnya, bukan penyempurnaan.
2. **Harness benchmark dikerjakan setelah M2, bukan sekarang.** Kalau dibuat sekarang
   ia mengukur worker pool lama, dan begitu pipeline jadi hampir semua metriknya harus
   ditulis ulang — `WORKER_COUNT` hilang, diganti byte budget dan limiter per stage.
3. **Artikel A dilepas dari seri.** Ditulis berdiri sendiri; artikel Kubernetes yang
   sudah terbit tidak diubah, cukup ditautkan setelah A terbit.
4. **Fase 5 adaptif (AIMD) tetap opsional dan paling akhir.** Limiter statik sudah
   cukup untuk Artikel B, dan angka statik justru lebih mudah dijelaskan.

---

## Keputusan yang masih terbuka

- **Kafka atau Redis sebagai target utama mode event.** Fase 0 membuktikan Redis list
  tidak punya ack — event hilang permanen kalau consumer mati. Kafka mengirim ulang.
  Keputusan ini menentukan apakah Strimzi perlu dideploy permanen.
- **Nasib blob `.exe` di history git.** Sudah untracked, tapi masih ada di setiap commit
  lama; klon tetap ~55 MB sampai history ditulis ulang.
- **Push branch dan buka PR, atau lanjut lokal** sampai M2 selesai.

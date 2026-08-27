# Catatan pengembangan s3nitor

Ringkasan apa yang terjadi sejauh ini, dari repo yang mangkrak sampai pipeline
berstage. Ditulis supaya gampang dibaca ulang, bukan sebagai dokumentasi teknis —
untuk itu ada `docs/roadmap.md` dan rencana implementasi di plan file.

**Posisi:** branch `feat/staged-pipeline-foundations`, 12 commit, belum di-push.
3.526 baris Go, 22 fungsi test di 5 paket. Sebelumnya: nol test.

---

## 1. Sebelum menulis kode baru, yang lama sudah bocor duluan

Tiga hal ketemu cuma dari membaca repo, dan ketiganya jenis kegagalan yang
**tidak memunculkan error**:

**File ignore-nya tidak pernah dibaca.** Namanya `gitignore`, tanpa titik di
depan. Akibatnya 55 MB artefak build Windows, database SQLite lokal, dan `.env`
ikut ter-track. Untungnya `.env`-nya ternyata identik byte-per-byte dengan
`env.example` — jadi tidak pernah ada kredensial asli yang ke-commit.

**`make release` menghasilkan binary rusak.** Cross-compile dengan `GOOS=...`
biasa membuat Go diam-diam menyetel `CGO_ENABLED=0`, dan driver SQLite lalu
menaut stub yang **kompilasi bersih tapi panic saat startup**:

```
failed init DB: Binary was compiled with 'CGO_ENABLED=0',
go-sqlite3 requires cgo to work. This is a stub
```

Aku buktikan langsung dengan menjalankan hasilnya. Artinya file `.exe` yang
selama ini ada di repo kemungkinan besar memang sudah rusak sejak awal.

**`-X main.Version` tidak pernah berlaku.** Makefile mengirim flag itu, tapi
tidak ada variabel `Version` yang dideklarasikan — dan linker mengabaikan `-X`
untuk simbol yang tidak ada, tanpa keluhan. Semua build selama ini tanpa versi.

> Pola yang berulang sepanjang proyek ini: yang berbahaya bukan error, tapi hal
> yang berhasil secara diam-diam.

---

## 2. Desain ulang: satu pool ternyata bentuk yang salah

Desain lama sederhana — daftar seluruh bucket, lalu `WORKER_COUNT` goroutine
mengerjakan tiap objek dari awal sampai akhir. Masalahnya satu angka disuruh
menjawab lima pertanyaan berbeda: kueri database, transfer jaringan, YARA yang
makan CPU, panggilan API pihak ketiga, dan tulis ke sink.

Yang paling tajam soal ukuran objek. Enam belas worker itu wajar untuk objek
10 KB. Enam belas worker yang sama untuk objek 1 GB berarti 16 GB data
sementara — karena batasnya menghitung **file**, dan file bukan sumber daya
yang langka.

Selama diskusi desain ada beberapa kali aku salah dan kamu yang mengoreksi:

- Aku merancang pool yang membesar kalau antriannya panjang. Salah. Antrian
  penuh cuma bilang permintaan melebihi throughput; dia tidak bilang apakah
  menambah concurrency akan menolong. Kalau YARA sudah memenuhi semua core,
  goroutine tambahan cuma menambah context switch.
- Aku masih terpaku hasil scan harus disatukan per file. Kamu menunjuk bahwa
  sink-nya NoSQL — tiap hasil scanner berdiri sendiri saja, cukup `file_id`-nya
  sama. Itu menghapus seluruh kebutuhan `ScanContext` yang mutable.
- Kamu menanyakan format notifikasi SeaweedFS. Itu yang memunculkan bahwa
  `ObjectRef` tidak boleh menyimpan `ETag`, tapi `Version` — karena SeaweedFS
  tidak punya ETag ala S3.

---

## 3. Fase 0: mengukur dulu sebelum membangun

Sebelum menulis satu baris pipeline, aku bangun harness sekali-pakai: nyalakan
storage dan broker sungguhan di cluster, upload file, baca event-nya, ambil
objeknya kembali, bandingkan byte-nya.

Tiga kombinasi lulus: **MinIO+Redis**, **MinIO+Kafka**, **SeaweedFS+Kafka**.

Dan **empat asumsi yang sudah kutulis di rencana ternyata salah**:

| Asumsi | Kenyataan |
|---|---|
| Spasi jadi `%20` | Jadi `+`, dan `/` jadi `%2F` |
| Bentuk payload tergantung vendor | Tergantung **transport** — MinIO yang sama, amplop beda ke Redis vs Kafka |
| Upload dilaporkan sebagai `:Put` | Streaming jadi `:CompleteMultipartUpload` |
| SeaweedFS tidak punya hash konten | Punya — MD5 base64 di chunk-nya |

Yang pertama paling licik. Di Go, `url.PathUnescape("with+space.pdf")`
mengembalikan `"with+space.pdf"` — plus-nya utuh, key-nya salah, **tanpa error**.
Cuma `QueryUnescape` yang benar. Bug ini tidak akan pernah kelihatan sampai ada
file yang namanya mengandung spasi.

Temuan yang paling berbahaya dari SeaweedFS: tiga upload menghasilkan **15 event
filer**, enam di antaranya menunjuk `.uploads/` — potongan multipart yang belum
jadi objek. Consumer yang mempercayainya akan memindai file parsial dan
menerbitkan temuan tentang objek yang tidak pernah ada.

Payload aslinya disimpan di `test/fixtures/` — nanti decoder-nya diuji lawan byte
sungguhan, bukan lawan deskripsiku tentang byte itu.

---

## 4. CVE: alat dengan angka lebih seram justru yang lebih banyak salah

Scan manifest melaporkan **28 kerentanan**, dua kritikal. Setelah dicek mana yang
benar-benar masuk dependency graph, **20 di antaranya paket SSH di
`golang.org/x/crypto`** — dan ini scanner object storage yang tidak pernah
membuka koneksi SSH.

Lalu `govulncheck`, yang menganalisis jalur panggilan, menemukan **14 yang sama
sekali tidak terlihat oleh scan manifest** — di pustaka standar: `net/url`,
`crypto/tls`, `crypto/x509`, terjangkau lewat klien S3 dan panggilan HTTP ke API
intel.

| | Scan manifest | Scan reachability |
|---|---|---|
| Dilaporkan | 28 | 14 |
| Benar terjangkau | 8 | 14 |
| Positif palsu | 20 | 0 |
| Pustaka standar | tidak terlihat | terlihat |

Upgrade dependency + patok `toolchain go1.25.13` → dua-duanya nol. Efek sampingan
bagus: `golang.org/x/crypto` **keluar total** dari dependency graph, jadi 20
temuan itu hilang, bukan sekadar turun versi.

---

## 5. M1 — mencabut state bersama

Tiap scanner dulu menerima pointer ke satu `ScanContext` dan menulis hasilnya ke
map di dalamnya. Aman **hanya karena** mereka jalan berurutan. Begitu dua scanner
jalan bersamaan — yang justru tujuan seluruh refactor ini — `sc.Results[nama] = …`
menjadi concurrent map write, dan Go menjawabnya dengan fatal error, bukan panic
yang bisa di-recover.

Solusinya bukan mutex. Map itu ada semata-mata karena hasilnya dikumpulkan; kalau
tiap scanner menerbitkan hasilnya sendiri, tidak ada yang perlu dikumpulkan:

```go
// sebelum: mutasi state bersama
Scan(ctx, sc *ScanContext) error
// sesudah: input read-only, kembalikan hasil sendiri
Scan(ctx, in *ScanInput) (Result, error)
```

Hashing berhenti jadi Scanner. Dia dulu wajib terdaftar pertama karena IOC dan
OTX membaca hash yang ditinggalkannya — dan itu membuat tiap objek dibaca dua
kali. Sekarang dia `io.Writer` yang di-tee ke download: byte dibaca sekali, dan
scanner analisis tidak lagi punya urutan wajib.

`FileRecord` juga berganti kunci ke `sha256(bucket ‖ key ‖ version)`. Melipat
versi ke dalam kunci membereskan dua jalur dedup yang selama ini saling
bertentangan menjadi satu: baris ada = konten persis ini sudah dipindai.

---

## 6. M2 — pipeline, dan tiga bug di kodeku sendiri

Empat stage, masing-masing dibatasi oleh sumber daya yang benar-benar habis:

```
discover ──► fetch+hash ──► analyze ──► publish
1 goroutine   byte budget   GOMAXPROCS  batch+flush
dedup batch   + slot conn               1 goroutine
```

Bagian yang menarik: **tiga bug ditemukan setelah kode ditulis, bukan sebelumnya.**

**Bug 1 — budget dilepas sebelum body ditutup.** Test byte budget gagal di
percobaan pertama: `peak = 6144, budget = 4096`. Aku melepas jatah sebelum
`body.Close()`, padahal buffer jaringan masih memegang datanya. Limiter dipatuhi,
tapi puncak sebenarnya tetap lewat.

**Bug 2 — objek yang dilewati hilang tanpa jejak.** Objek di atas
`MAX_OBJECT_SIZE` cuma dapat baris log dan penambahan counter. Untuk scanner
keamanan itu buruk: objek terbesar di bucket justru tempat paling mungkin sesuatu
disembunyikan. Sekarang dia menerbitkan dokumen `scanned: false` ke sink yang
sama, jadi alerting yang sudah ada ikut menangkapnya.

**Bug 3 — yang paling parah, dan muncul dari pertanyaanmu.** Kamu bertanya soal
antrian setelah scan. Waktu menelusurinya aku lihat budget dilepas setelah
transfer, padahal file temp baru dihapus setelah scan. Di antaranya, file itu ada
di disk dan tidak ada yang menghitungnya:

```
STAGE_QUEUE_SIZE = 1000  ×  objek 100 MB  =  100 GB disk temp
FETCH_BYTE_BUDGET = 512 MB
```

Lebih jauh, itu diam-diam menghapus rem global yang jadi dasar desainnya: fetch
seharusnya kehabisan token kalau hilir macet, tapi karena budget sudah
dikembalikan, dia tidak pernah mengerem.

Perbaikannya memisahkan dua sumber daya yang umur pakainya beda: **slot koneksi**
dilepas begitu transfer selesai, **budget byte** ikut payload sampai file-nya
dihapus.

---

## 7. Posisi sekarang

**Sudah jalan:** git bersih dan CI ada, dependency dan toolchain nol CVE, tiga
jalur event tervalidasi lawan infra sungguhan, interface scanner tanpa state
bersama, pipeline empat stage dengan batas per-resource, exporter Prometheus.

**Belum:** lane per scanner + spill ke `scan_tasks` (M4), source event
Redis/Kafka (M5), harness sizing (M3), dashboard (M6).

**Tulisan:** draft artikel selesai dan berdiri sendiri, tinggal ekspor dua
diagram ke PNG. Artikel benchmark menunggu M3.

Satu hal yang aku jaga sepanjang tulisan itu: pipeline-nya **belum selesai** waktu
draft ditulis — desainnya sudah, integrasi berisikonya sudah terbukti,
implementasinya belum. Mengklaim sudah jadi bakal ketahuan begitu ada yang
membuka repo-nya.

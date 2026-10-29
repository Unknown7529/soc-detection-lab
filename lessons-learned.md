# Lessons Learned

Masalah yang ditemui selama membangun lab, penyebab, dan solusinya.

| # | Masalah | Penyebab | Solusi |
|---|---|---|---|
| 1 | Sysmon tidak muncul di Splunk, `splunkd.log` menunjukkan errorCode=5 | UF tidak punya izin membaca channel `Microsoft-Windows-Sysmon/Operational` (Access Denied) | Tambahkan SID service UF ke ACL channel, dan jalankan service UF sebagai LocalSystem (`sc config SplunkForwarder obj= LocalSystem`). Di produksi, prinsip least privilege lebih dipilih |
| 2 | `Sysmon64.exe -i` gagal: "Failed to open xml configuration" | File `sysmonconfig-export.xml` belum ada di folder | Unduh config dengan `Invoke-WebRequest`, cek isinya dengan `Get-Content`, lalu install ulang |
| 3 | Instalasi Atomic Red Team gagal: modul `powershell-yaml` tidak ditemukan | PSGallery belum terdaftar, TLS 1.2 belum diaktifkan, NuGet lama | Aktifkan TLS 1.2, install NuGet, `Register-PSRepository -Default`, lalu `Install-Module powershell-yaml` |
| 4 | `Invoke-AtomicTest`: "Found 0 atomic tests" | Folder `atomics` tidak terunduh (instalasi terhenti), `master.zip` kosong setelah diekstrak | Unduh hanya file YAML teknik yang dipakai lewat `Invoke-WebRequest` |
| 5 | Import modul Atomic gagal: "running scripts is disabled" | `Set-ExecutionPolicy Bypass -Scope Process` hanya berlaku di satu sesi PowerShell | Jalankan ulang perintah itu di setiap sesi baru |
| 6 | Alert SOC-001 memicu berulang tiap 5 menit tanpa serangan baru | Time range tersimpan sebagai rentang tanggal tetap dari pengujian query | Ganti ke jendela relatif 15 menit, mode Once, throttle 15 menit |
| 7 | Save alert ditolak: "Per result alert throttling requires at least one throttling field" | Mode trigger For each result mewajibkan field throttle | Pakai mode Once |
| 8 | Triggered Alerts kosong padahal alert sempat menyala | Expires terlalu pendek (catatan trigger terhapus) | Set Expires 7 hari |
| 9 | Jam di Splunk berbeda 7 jam dari jam VM | Splunk menampilkan UTC, VM memakai WIB | Ubah zona waktu di Preferences Splunk ke Jakarta (GMT+7) |
| 10 | Query PowerShell terlalu longgar menangkap `CompatTelRunner.exe` | `-ExecutionPolicy` diawali `-e` | Regex mewajibkan spasi sebelum dan sesudah parameter |
| 11 | Event setup Windows memicu rule SOC-006 | Pembuatan `defaultuser0`/`WDAGUtilityAccount` dan akun pengguna pertama masuk grup Administrators | Dokumentasikan pembeda (pembuat akun mesin, nama host sementara) sebagai false positive |
| 12 | Hasil 4625 tampil dua baris untuk satu serangan | Field `Account_Name` muncul dua kali (Subject dan target) | Ambil akun target dengan `mvindex(Account_Name,-1)` |
| 13 | Trigger SOC-005 muncul dua kali untuk satu event | Jendela 15 menit melewati beberapa eksekusi jadwal 5 menit | Throttle 15 menit |
| 14 | Waktu deteksi lebih lama dari yang dikira | Cron 5 menit ditambah jeda ingest, terukur sekitar 8-9 menit | Catat angka sebenarnya di laporan; interval lebih pendek atau real-time alert untuk deteksi lebih cepat |

## Hal yang dipelajari

- Rule berbasis jendela waktu harus diuji setelah alert disimpan, bukan sebelum.
- Rule yang terlalu longgar menghasilkan false positive; regex perlu diuji terhadap data nyata.
- Screenshot bukti Splunk tidak bisa diulang setelah trial habis, jadi cadangkan SPL, XML dashboard, dan screenshot lebih awal.
- Dokumentasikan false positive dan keterbatasan rule dengan jujur.

# SOC-001: Brute Force SMB

| Atribut | Nilai |
|---|---|
| Severity | High |
| MITRE ATT&CK | T1110.001 (Brute Force: Password Guessing) |
| Tactic | Credential Access |
| Sumber log | Windows Security, EventCode 4625 |
| Jadwal | Setiap 5 menit (`*/5 * * * *`), jendela 15 menit |
| Trigger | Number of Results > 0, mode Once |
| Throttle | 15 menit |
| Expires | 7 hari |

## Logika

Satu IP sumber menghasilkan 10 atau lebih logon gagal (4625). Field `Account_Name` pada 4625 muncul dua kali (akun Subject dan akun target), jadi akun target diambil dengan `mvindex(Account_Name,-1)`.

## Query

```
index=lab_soc source="WinEventLog:Security" EventCode=4625 Source_Network_Address!="-"
| eval target_account=mvindex(Account_Name,-1)
| stats count, dc(target_account) as accounts, min(_time) as first_seen, max(_time) as last_seen by Source_Network_Address, Logon_Type
| where count>=10
| convert ctime(first_seen) ctime(last_seen)
```

## Validasi

- Serangan: loop `net use` dari host (`192.168.229.1`) ke VM, akun `administrator`, Logon Type 3.
- Serangan kedua dimulai 09:52, login gagal terakhir 09:53:10, alert menyala 09:55:07 (sekitar 2 menit sejak percobaan terakhir).
- Bukti: [query](screenshots/soc-001-query-result.png), [triggered alert](screenshots/soc-001-triggered-alert.png), [konfigurasi](screenshots/soc-001-alert-config.png).

## False positive

- Pengguna lupa password atau mengetik salah berulang.
- Service account atau aplikasi dengan kredensial kedaluwarsa.
- Pemindai kerentanan atau tool monitoring internal yang mencoba login.

## Tuning

- Kecualikan IP scanner dan monitoring yang dikenal.
- Naikkan threshold atau perpanjang jendela di jaringan yang ramai.
- Pertimbangkan membedakan Logon Type 3 (jaringan) dan 10 (RDP).

## Respons L1

1. Catat IP sumber, akun target, jumlah percobaan, dan rentang waktu.
2. Cek apakah ada logon sukses (4624) dari IP yang sama setelah kegagalan.
3. Cek apakah akun terkunci (4740) atau kebijakan lockout berlaku.
4. Cek apakah IP sumber internal yang dikenal atau eksternal.
5. Eskalasi ke L2 jika ada logon sukses setelah banyak kegagalan, atau jika sumber tidak dikenal.

## Catatan tuning yang pernah terjadi

Alert awalnya memicu berulang tiap 5 menit tanpa serangan baru karena time range tersimpan sebagai rentang tanggal tetap dari pengujian. Perbaikan: jendela relatif 15 menit, mode Once, throttle 15 menit. Lihat [duplicate triggers](screenshots/soc-001-duplicate-triggers.png).

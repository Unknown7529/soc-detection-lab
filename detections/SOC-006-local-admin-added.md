# SOC-006: Member Added to Local Administrators

| Atribut | Nilai |
|---|---|
| Severity | High |
| MITRE ATT&CK | T1136.001 (Create Account: Local Account), T1098 (Account Manipulation) |
| Tactic | Persistence, Privilege Escalation |
| Sumber log | Windows Security, EventCode 4720 dan 4732 |
| Jadwal | Setiap 5 menit, jendela 15 menit |
| Trigger | Number of Results > 0, mode Once |
| Throttle | 15 menit |
| Expires | 7 hari |

## Logika

Event 4732 (anggota ditambahkan ke grup lokal) untuk grup `Administrators` (SID `S-1-5-32-544`). Event 4720 (akun dibuat) dipakai sebagai konteks investigasi.

## Query

```
index=lab_soc source="WinEventLog:Security" EventCode=4732 Group_Name=Administrators
| table _time, host, Group_Name, Member_Security_ID
| sort _time
```

## Validasi

- Atomic Red Team T1136.001-8 membuat akun `T1136.001_Admin`: 4720 pada 2026-10-27 20:08:22.579, 4732 untuk `Users` pada 20:08:22.612, 4732 untuk `Administrators` pada 20:08:22.640 (selisih sekitar 61 milidetik).
- Tes alert: akun `SOC006Test` dan `SOC006Try` dibuat dan dimasukkan ke Administrators beberapa kali pada 2026-10-28 (12:48, 13:07, 15:42).
- Bukti: [query](screenshots/soc-006-query-result.png), [akun dibuat](screenshots/soc-006-account-exists.png), [triggered alert](screenshots/soc-006-triggered-alert.png), [hasil](screenshots/soc-006-alert-result.png), [konfigurasi](screenshots/soc-006-alert-config.png), [cleanup](screenshots/soc-006-cleanup.png).

## False positive

Event dari proses setup Windows ikut tercatat: `defaultuser0` (akun sementara OOBE) dan `WDAGUtilityAccount`, serta akun pengguna pertama yang dijadikan administrator. Ciri pembeda:
- Pembuat akun adalah akun mesin (nama berakhiran `$`) dengan nama komputer sementara.
- Event setup tercatat dengan nama host sementara (`DESKTOP-1LQT84G`), sedangkan aktivitas serangan tercatat pada host final (`Win10-SOC-LAB`).
- Akun sementara sudah tidak ada setelah setup selesai.

Bukti: [event setup](screenshots/soc-006-false-positive-oobe.png).

Penyebab lain di lingkungan nyata: admin IT menambah akun resmi, dan instalasi software yang membuat akun service.

## Tuning

- Kecualikan pembuat akun mesin pada jendela provisioning atau akun dari proses imaging. Jangan mengecualikan semua akun berakhiran `$` secara permanen, karena penyerang bisa memanfaatkannya.
- Cocokkan dengan tiket perubahan.

## Respons L1

1. Baca `Subject` pada event: siapa yang menambahkan.
2. Cek apakah akun masih ada dan kapan dibuat (4720).
3. Cek apakah ada tiket perubahan atau provisioning host baru.
4. Cek aktivitas akun tersebut setelahnya (logon 4624).
5. Eskalasi ke L2 jika akun tidak dikenal atau tidak ada tiket.

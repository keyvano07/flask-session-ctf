# 🔐 Flask Session Challenge - CTF Project

**Author:** Keyvano  
**Category:** Web Exploitation  
**Difficulty:** Easy

---

## 📝 Description

A Flask web application that stores session data. Can you retrieve the secret key and get the flag?

This challenge exploits insecure Flask session handling where sensitive data is stored in client-side cookies.

---

## 🏴 Flag

```
UbigCTF{Keyvano_Ganteng_kwokwokw_canda}
```

---

## 🎯 Challenge Overview

**Vulnerability:** Insecure Flask Session Handling

Flask sessions are signed but NOT encrypted. This application mistakenly stores the `app.secret_key` directly in the session cookie, allowing attackers to decode and extract it.

---

## 🚀 Deployment

### Local Development

```bash
# Run locally
cd src
python main.py
```

Access at: `http://localhost:5000`

### Docker Deployment

```bash
docker-compose up --build --detach
```

### Vercel Deployment

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/keyvano07/flask-session-ctf)

```bash
# Or using Vercel CLI
npm i -g vercel
vercel
```

---

## 🛠️ Tools

### Automatic Solver

```bash
python solve.py
```

The automatic solver will:
1. Visit `/flag` endpoint to get session cookie
2. Decode the Flask session cookie
3. Extract the secret key
4. Submit it to get the flag

---

## 💡 Hints

* **Hint 1:** Flask sessions are stored as cookies and can be decoded
* **Hint 2:** Look for the `session` cookie in your browser's Developer Tools
* **Hint 3:** The secret key is base64-encoded in the session

---

## 📚 Solution Guide

See `SOLUTION.md` for detailed step-by-step solution in Indonesian.

---

## 🏷️ Tags

`flask`, `web exploitation`, `session`, `cookie`, `ctf`

---

## 📄 License

This project is for educational purposes only.

---

**Made with ❤️ for CTF enthusiasts**

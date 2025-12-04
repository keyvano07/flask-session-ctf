from base64 import b64encode
import os 
from flask import Flask, request, session
from .flag import flag 

app = Flask(__name__) 
app.secret_key = os.urandom(64)

@app.route('/') 
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secret Vault</title>
        <style>
            body {
                font-family: 'Courier New', monospace;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                margin: 0;
            }
            .container {
                background: white;
                padding: 50px;
                border-radius: 15px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                text-align: center;
                max-width: 500px;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
                font-size: 2.5em;
            }
            p {
                color: #666;
                font-size: 1.2em;
                margin: 20px 0;
            }
            .flag-link {
                display: inline-block;
                margin-top: 30px;
                padding: 15px 40px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-decoration: none;
                border-radius: 30px;
                font-size: 1.2em;
                transition: transform 0.2s;
            }
            .flag-link:hover {
                transform: scale(1.05);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Secret Vault</h1>
            <p>Can you find the hidden secret?</p>
            <a href="/flag" class="flag-link">Enter Vault</a>
        </div>
    </body>
    </html>
    """

@app.route("/flag") 
def get_flag():
    session['sk'] = app.secret_key 
    sk = request.args.get('sk')
    
    if sk:
        secret_key_encoded = b64encode(app.secret_key).decode('utf-8')
        if sk == secret_key_encoded: 
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Success!</title>
                <style>
                    body {{
                        font-family: 'Courier New', monospace;
                        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
                        height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        margin: 0;
                    }}
                    .container {{
                        background: white;
                        padding: 50px;
                        border-radius: 15px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                        text-align: center;
                    }}
                    h1 {{ color: #11998e; font-size: 2.5em; }}
                    .flag {{ 
                        background: #f0f0f0;
                        padding: 20px;
                        border-radius: 10px;
                        font-size: 1.5em;
                        margin: 20px 0;
                        color: #333;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🎉 Congratulations!</h1>
                    <div class="flag">{flag}</div>
                    <a href="/" style="color: #11998e;">Back to Home</a>
                </div>
            </body>
            </html>
            """
        else:
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body {
                        font-family: 'Courier New', monospace;
                        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                        height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        margin: 0;
                    }
                    .container {
                        background: white;
                        padding: 50px;
                        border-radius: 15px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                        text-align: center;
                    }
                    h1 { color: #f5576c; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Access Denied</h1>
                    <p>Wrong secret key!</p>
                    <a href="/flag" style="color: #f5576c;">Try Again</a>
                </div>
            </body>
            </html>
            """
    else:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vault</title>
            <style>
                body {
                    font-family: 'Courier New', monospace;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin: 0;
                }
                .container {
                    background: white;
                    padding: 50px;
                    border-radius: 15px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                    text-align: center;
                }
                h1 { color: #667eea; }
                p { color: #666; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 Vault Locked</h1>
                <p>You need a secret key to access the flag.</p>
                <p>Find it and use: <code>/flag?sk=YOUR_SECRET</code></p>
                <a href="/" style="color: #667eea;">Back to Home</a>
            </div>
        </body>
        </html>
        """

# Vercel serverless function handler
handler = app

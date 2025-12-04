from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import re
import uvicorn

app = FastAPI()
security = HTTPBasic()

# ===== CONFIG =====

USERNAME = "admin"
PASSWORD = "securepassword"

# ===== AUTH =====

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# ===== PASSWORD LOGIC =====

def check_strength(password: str) -> str:
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[^A-Za-z0-9]", password): score += 1

    if score <= 2:
        return "WEAK"
    elif score == 3:
        return "MEDIUM"
    else:
        return "STRONG"

def check_breach(password: str) -> str:
    breached_passwords = ["123456", "password", "qwerty", "admin", "letmein"]
    return "BREACHED" if password.lower() in breached_passwords else "SAFE"

def ai_recommendation(password: str, strength: str, breach_status: str) -> str:
    if breach_status == "BREACHED":
        return "⚠️ รหัสผ่านนี้เคยรั่วไหล! แนะนำให้เปลี่ยนทันที"
    elif strength == "WEAK":
        return "❌ รหัสผ่านอ่อนแอ เพิ่มความยาวและความซับซ้อน เช่น ตัวพิมพ์ใหญ่ ตัวเลข และอักขระพิเศษ"
    elif strength == "MEDIUM":
        return "⚡ รหัสผ่านปานกลาง แนะนำเพิ่มความซับซ้อนเพื่อความปลอดภัยมากขึ้น"
    else:
        return "✅ รหัสผ่านแข็งแกร่ง! แต่อย่าลืมเปลี่ยนเป็นระยะ"

# ===== HTML TEMPLATES =====

HOME_HTML = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 Password Security Checker</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .user-info {{
            background: #f0f4ff;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 30px;
            color: #667eea;
            font-weight: 600;
        }}
        form {{
            text-align: left;
        }}
        label {{
            display: block;
            color: #333;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 14px;
        }}
        input[type="password"] {{
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s;
            margin-bottom: 20px;
        }}
        input[type="password"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        button {{
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }}
        button:active {{
            transform: translateY(0);
        }}
        .info {{
            margin-top: 20px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 10px;
            font-size: 12px;
            color: #666;
            text-align: left;
        }}
        .info h3 {{
            margin-bottom: 10px;
            color: #333;
            font-size: 14px;
        }}
        .info ul {{
            margin-left: 20px;
            line-height: 1.8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Password Security Checker</h1>
        <p class="subtitle">ตรวจสอบความปลอดภัยของรหัสผ่านของคุณ</p>
        <div class="user-info">
            👤 เข้าสู่ระบบเป็น: {user}
        </div>
        <form method="POST" action="/check-password">
            <label for="password">รหัสผ่านที่ต้องการตรวจสอบ:</label>
            <input 
                type="password" 
                id="password" 
                name="password" 
                placeholder="กรุณาใส่รหัสผ่าน..."
                required
                autocomplete="off"
            >
            <button type="submit">🔍 ตรวจสอบรหัสผ่าน</button>
        </form>
        <div class="info">
            <h3>ℹ️ ข้อมูลเพิ่มเติม</h3>
            <ul>
                <li>ระบบจะตรวจสอบความแข็งแกร่งของรหัสผ่าน</li>
                <li>ตรวจสอบว่ารหัสผ่านเคยรั่วไหลหรือไม่</li>
                <li>ให้คำแนะนำเพื่อปรับปรุงความปลอดภัย</li>
                <li>ข้อมูลรหัสผ่านไม่ถูกบันทึกหรือเก็บไว้</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""

RESULT_HTML = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📊 ผลการตรวจสอบรหัสผ่าน</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 600px;
            width: 100%;
            padding: 40px;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
            text-align: center;
        }}
        .user-info {{
            background: #f0f4ff;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 30px;
            color: #667eea;
            font-weight: 600;
            text-align: center;
        }}
        .result-section {{
            margin-bottom: 25px;
            padding: 20px;
            border-radius: 15px;
            border-left: 5px solid;
        }}
        .strength {{
            background: #f9f9f9;
        }}
        .strength.weak {{
            border-left-color: #e74c3c;
            background: #fee;
        }}
        .strength.medium {{
            border-left-color: #f39c12;
            background: #fff8e1;
        }}
        .strength.strong {{
            border-left-color: #27ae60;
            background: #e8f5e9;
        }}
        .breach {{
            background: #f9f9f9;
        }}
        .breach.safe {{
            border-left-color: #27ae60;
            background: #e8f5e9;
        }}
        .breach.breached {{
            border-left-color: #e74c3c;
            background: #fee;
        }}
        .section-title {{
            font-size: 14px;
            color: #666;
            margin-bottom: 8px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section-value {{
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 10px;
        }}
        .strength.weak .section-value {{
            color: #e74c3c;
        }}
        .strength.medium .section-value {{
            color: #f39c12;
        }}
        .strength.strong .section-value {{
            color: #27ae60;
        }}
        .breach.safe .section-value {{
            color: #27ae60;
        }}
        .breach.breached .section-value {{
            color: #e74c3c;
        }}
        .ai-suggestion {{
            background: #e3f2fd;
            padding: 20px;
            border-radius: 15px;
            border-left: 5px solid #2196f3;
            margin-bottom: 30px;
        }}
        .ai-suggestion .section-title {{
            color: #1976d2;
            margin-bottom: 12px;
        }}
        .ai-suggestion-text {{
            color: #333;
            font-size: 15px;
            line-height: 1.6;
        }}
        .buttons {{
            display: flex;
            gap: 15px;
        }}
        button {{
            flex: 1;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-secondary {{
            background: #f5f5f5;
            color: #333;
            border: 2px solid #e0e0e0;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }}
        button:active {{
            transform: translateY(0);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 ผลการตรวจสอบรหัสผ่าน</h1>
        <div class="user-info">
            👤 ผู้ใช้: {user}
        </div>
        
        <div class="result-section strength {strength_class}">
            <div class="section-title">ความแข็งแกร่ง</div>
            <div class="section-value">{strength}</div>
        </div>
        
        <div class="result-section breach {breach_class}">
            <div class="section-title">สถานะการรั่วไหล</div>
            <div class="section-value">{breach_status}</div>
        </div>
        
        <div class="ai-suggestion">
            <div class="section-title">💡 คำแนะนำจาก AI</div>
            <div class="ai-suggestion-text">{ai_suggestion}</div>
        </div>
        
        <div class="buttons">
            <button class="btn-secondary" onclick="window.history.back()">← ย้อนกลับ</button>
            <button class="btn-primary" onclick="window.location.href='/'">🏠 หน้าหลัก</button>
        </div>
    </div>
</body>
</html>
"""

# ===== ROUTES =====

@app.get("/", response_class=HTMLResponse)
def home(user: str = Depends(authenticate)):
    return HOME_HTML.format(user=user)

@app.post("/check-password", response_class=HTMLResponse)
def check_password_web(
    password: str = Form(...),
    user: str = Depends(authenticate)
):
    strength = check_strength(password)
    breach_status = check_breach(password)
    ai_suggestion = ai_recommendation(password, strength, breach_status)

    strength_class = strength.lower()
    breach_class = breach_status.lower()

    return RESULT_HTML.format(
        user=user,
        strength=strength,
        strength_class=strength_class,
        breach_status=breach_status,
        breach_class=breach_class,
        ai_suggestion=ai_suggestion
    )

# ===== RUN SERVER =====

if __name__ == "__main__":
    print("🚀 Starting Password Security Checker…")
    print("📍 URL: http://127.0.0.1:8000")
    print("🔒 Mode: LOCALHOST ONLY (Private)")
    print(f"🔐 Username: {USERNAME}")
    print(f"🔑 Password: {PASSWORD}")
    print("\n⚠️  เว็บนี้เข้าได้แค่เครื่องนี้เท่านั้น")
    uvicorn.run(app, host="127.0.0.1", port=8000)


from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import uuid4
import sqlite3

# =========================
# CONFIG & SECURITY
# =========================
SECRET_KEY = "DUNYAYA_ACILACAK_GIZLI_ANAHTAR" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24 # 1 gün sürsün

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="EsnafKasasi_Global")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# DATABASE SETUP (SQLite)
# =========================
def get_db():
    conn = sqlite3.connect("finans.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    # Kullanıcılar Tablosu
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        hashed_password TEXT,
        created_at TEXT
    )""")
    # İşlemler Tablosu
    db.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        title TEXT,
        amount REAL,
        type TEXT,
        category TEXT,
        created_at TEXT,
        owner_email TEXT,
        FOREIGN KEY(owner_email) REFERENCES users(email)
    )""")
    db.commit()

init_db()

# =========================
# MODELS
# =========================
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class TransactionCreate(BaseModel):
    title: str
    amount: float
    type: str 
    category: str

class TransactionOut(BaseModel):
    id: str
    title: str
    amount: float
    type: str
    category: str
    created_at: str
    owner_email: str

# =========================
# HELPERS
# =========================
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None: raise HTTPException(status_code=401)
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Oturum süresi dolmuş")

# =========================
# ROUTES
# =========================

@app.post("/auth/register")
def register(req: RegisterRequest):
    db = get_db()
    hashed = pwd_context.hash(req.password)
    try:
        db.execute("INSERT INTO users VALUES (?, ?, ?)", 
                   (req.email.lower(), hashed, datetime.now().isoformat()))
        db.commit()
        return {"message": "Kayıt başarılı"}
    except:
        raise HTTPException(status_code=400, detail="Bu email zaten kayıtlı")

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (form_data.username.lower(),)).fetchone()
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Hatalı giriş")
    
    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/transactions")
def add_transaction(tx: TransactionCreate, email: str = Depends(get_current_user)):
    db = get_db()
    tx_id = str(uuid4())
    db.execute("INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?)",
               (tx_id, tx.title, tx.amount, tx.type, tx.category, datetime.now().isoformat(), email))
    db.commit()
    return {"id": tx_id}

@app.get("/transactions", response_model=List[TransactionOut])
def list_transactions(email: str = Depends(get_current_user)):
    db = get_db()
    rows = db.execute("SELECT * FROM transactions WHERE owner_email = ?", (email,)).fetchall()
    return [dict(row) for row in rows]

@app.delete("/transactions/{tx_id}")
def delete_transaction(tx_id: str, email: str = Depends(get_current_user)):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE id = ? AND owner_email = ?", (tx_id, email))
    db.commit()
    return {"status": "ok"}
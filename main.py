from fastapi import FastAPI, UploadFile, File, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt
import pandas as pd
import psycopg2
import bcrypt
import datetime
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET = "secret123"

# ---------------- AUTH ----------------
def init_db():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
                   id SERIAL PRIMARY KEY,
                   name TEXT UNIQUE,
                   password BYTEA
                   )


""")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_data (
                   id SERIAL PRIMARY KEY,
                   data TEXT,
                   user_id TEXT
                   )
""")
    
    conn.commit()
    conn.close()

init_db()

def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(401, "No token")

    token = authorization.split(" ")[1]

    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(401, "Invalid token")


def create_token(data):
    data["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    return jwt.encode(data, SECRET, algorithm="HS256")


# ---------------- DB ----------------
def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode="require"
    )

# ---------------- MODELS ----------------
class User(BaseModel):
    name: str
    password: str






# ---------------- AUTH ENDPOINTS ----------------

@app.get("/")
def home():
    return {
        "status": "API running",
        "docs": "/docs",
        "endpoints": ["/login", "/upload", "/stats"]
    }

@app.post("/register")
def register(user: User):
    conn = get_conn()
    cursor = conn.cursor()

    hashed = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO users (name, password) VALUES (%s, %s)",
        (user.name, hashed)
    )

    conn.commit()
    conn.close()

    return {"message": "user created"}

@app.post("/login")
def login(user: User):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE name = %s",
        (user.name,)
    )

    result = cursor.fetchone()
    conn.close()

    if not result:
        return {"error": "invalid credentials"}
    
    stored_password = bytes(result[0])

    if bcrypt.checkpw(user.password.encode(), stored_password):
        token = create_token({"sub": user.name})
        return {"token": token}

    return {"error": "invalid credentials"}

# ---------------- UPLOAD ----------------
@app.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(verify_token)):
    df = pd.read_csv(file.file)

    conn = get_conn()
    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute(
            "INSERT INTO uploaded_data (data, user_id) VALUES (%s, %s)",
            (row.to_json(), user["sub"])
        )

    conn.commit()
    conn.close()

    return {"status": "saved"}

# ---------------- STATS ----------------

@app.get("/me")
def me(user=Depends(verify_token)):
    return {"user": user["sub"]}


@app.get("/stats")
def stats(user=Depends(verify_token)):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM uploaded_data WHERE user_id = %s",
        (user["sub"],)
    )

    count = cursor.fetchall()[0]
    
    conn.close()
    
    return {
        "rows": count,
        "user": user["sub"]
    }

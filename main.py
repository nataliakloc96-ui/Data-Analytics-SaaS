from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt 
from fastapi import Header, HTTPException
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

class User(BaseModel):
    name: str
    password: str

conn = psycopg2.connect(
    dbname=os.getenv["DB_NAME"],
    user=os.getenv["DB_USER"],
    password=os.getenv["DB_PASS"],
    host=os.getenv["DB_HOST"],
    port=os.getenv["DB_PORT"]
)



@app.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(verify_token)):
    df = pd.read_csv(file.file)

    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute(
            "INSERT INTO uploaded_data (data, user_id) VALUES (%s, %s)",
            (row.to_json(), user["sub"])
        )
    conn.commit()

    return {"status": "saved"
    }

@app.get("/stats")
def get_stats(user=Depends(verify_token)):
    cursor = conn.cursor()

    cursor.execute(
        "SELECT data FROM uploaded_data WHERE user_id = %s",
        (user["sub"],)
        
        )
    rows = cursor.fetchall()

    return {"rows": len(rows)}

    
@app.post("/register")
def register(user: User):
    cursor = conn.cursor()

    hashed = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO users (name, password) VALUES (%s, %s)",
        (user.name, hashed)
    )
    conn.commit()

    return {"message": "user created"}

SECRET = "secret123"

def create_token(data):
    data["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    return jwt.encode(data, SECRET, algorithm="HS256")

@app.post("/login")
def login(user: User):
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE name = %s",
        (user.name,)
    )

    result = cursor.fetchone()

    if not result:
        return {"error": "invalid credentials"}
    
    if bcrypt.checkpw(user.password.encode(), result[0].tobytes()):
        token = create_token({"sub": user.name})
        return {"token": token}
    
    return {"error": "invalid credentials"}

def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(401, "No token")
    
    token = authorization.split(" ")[1]

    try:
        jwt.decode(token, SECRET, algorithms=["HS256"])
    
    except:
        raise HTTPException(401, "Invalid token")
    
@app.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(verify_token)):
    df = pd.read_csv(file.file)

    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute(
            "INSERT INTO uploaded_data (data, user_id) VALUES (%s, %s)",
            (row.to_json(), user["sub"])
        )
    
    conn.commit()

    return {"status": "saved"}

@app.get("/stats")
def stats(user=Depends(verify_token)):
    cursor = conn.cursor()

    cursor.execute(
        "SELECT data FROM users WHERE user_id = %s",
        (user["sub"],)
    )

    rows = cursor.fetchall()

    return {"rows": len(rows)}

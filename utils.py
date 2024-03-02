import asyncio
import time
from jose import JWTError, jwt
from config.config import SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, Depends, status
from base.class_base import Admin, OTP, Service, ServiceDuration
from jose import JWTError, jwt
import random
from sqlalchemy.orm import Session
from datetime import datetime

# Thêm danh sách đen cho token
token_blacklist: set = set()

# OAuth2PasswordBearer cho việc xác thực token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def random_id(K: int = 5):
    randoms = ''.join(random.choices('0123456789', k=K))
    return randoms

# Hàm tạo JWT token
def create_jwt_token(data: dict):
    data["iat"] = time.time()
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Hàm xác minh JWT token
def verify_jwt_token(token: str = Depends(oauth2_scheme)):
    if token in token_blacklist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been invalidated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Hàm lấy thông tin người dùng từ cơ sở dữ liệu
async def get_admin(db, username: str):
    query = Admin.__table__.select().where(Admin.username == username)
    user = await db.fetch_one(query)
    return user

async def delete_otp_after_delay(email: str, db: Session):
    await asyncio.sleep(60)
    delete_query = OTP.__table__.delete().where(OTP.email == email)
    await db.execute(delete_query)

async def get_select_service(db):
    query = Service.__table__.select()
    service = await db.fetch_all(query)
    return service

async def get_select_service_duration(db):
    query = ServiceDuration.__table__.select()
    service_duration = await db.fetch_all(query)
    return service_duration
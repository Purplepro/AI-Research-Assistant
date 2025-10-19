from datetime import datetime, timedelta, timezone
from typing import Annotated
from pydantic import BaseModel

import jwt
from jwt.exceptions import InvalidTokenError
from sqlmodel import Field, Session, SQLModel, create_engine, select
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import Depends, FastAPI, HTTPException, status

SECRET_KEY = "891a561ea143dcaf84a76a443ebc3af81706af10cbcf5c10284679be1219dcb9"
ALGORITHM = "HS256"


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    
# may need function called UserInDB


class User(SQLModel, table=True):
    user_id: int | None = Field(unique=True, default=None, primary_key=True)
    name: str = Field(index=True)
    username: str = Field(default=None, unique=True, primary_key=True)
    password_hash: str = Field(max_length=255)
    email: str = Field()
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)
    
   
def get_password_hash(password = str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

    
    
class User_Knowledge_Base(SQLModel, table=True):
    id: int | None = Field(unique=True, default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user_message: str
    llm_response: str 
    script: str
    
    
class Conversation(SQLModel, table=True):
    id = int | None = Field(default=None, primary_key=True)
    
class UserInDB(User):
    hashed_password: str
    
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username:str, password:str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    creditials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED
        detail="Could not validate creditials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(Token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise creditials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise creditials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise creditials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
    

    
    
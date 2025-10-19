import logging
from typing import Annotated
from datetime import datetime, timedelta

from fastapi.security import OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status

from database.schema import Token, User, authenticate_user, create_access_token, get_current_active_user, fake_users_db

ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()


#POST
@app.post("/token")
async def login_for_accoess_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
            )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
# GET

@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/knowledgebase")
async def knowledgebase():
    return {"message": "Hello! This is your personal knowledge base page where all are you passed research requests is stored."}

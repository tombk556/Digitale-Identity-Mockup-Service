from app import models
from app.db import PostgresDB
from app.config import settings
from app.auth import oauth2, schemas
from app.auth.certificate import create_file

import os
import uuid
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

auth = APIRouter(
    prefix="/auth",
    tags=["Authentication"])

PRIVATE_KEY_DIRECTORY = settings.private_key_directory

os.makedirs(PRIVATE_KEY_DIRECTORY, exist_ok=True)


@auth.post("/sign_up", status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(PostgresDB.get_db)):
    existing_user = db.query(models.User).filter(
        (models.User.email == user.email) | (models.User.username == user.username)).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exist"
        )
    
    id = uuid.uuid4()
    download_url, public_key = create_file(str(id), user.username)
    
    user.password = oauth2.hash(user.password)
    new_user = models.User(id=id, email=user.email, username=user.username, 
                           password=user.password, name=user.name, age=user.age, 
                           public_key=public_key)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return download_url
    
    


@auth.post("/login", response_model=schemas.Token)
def login(user_credentials: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(PostgresDB.get_db)):
    user = db.query(models.User).filter(
        (models.User.email == user_credentials.username) |
        (models.User.username == user_credentials.username)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User does not exist")

    if not oauth2.verify(user_credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid Credentials")

    access_token = oauth2.create_access_token(data={"user_id": str(user.id)})

    return {"access_token": access_token, "token_type": "bearer"}


@auth.delete("/delete_user", status_code=status.HTTP_204_NO_CONTENT)
def delte_user(current_user: schemas.User = Depends(oauth2.get_current_user), db: Session = Depends(PostgresDB.get_db)):

    existing_user = db.query(models.User).filter(
        models.User.id == current_user.id)

    if not existing_user.first():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist"
        )

    existing_user.delete(synchronize_session=False)
    db.commit()
    return 204


@auth.put("/update_user", response_model=schemas.User)
def update_user(update_user: schemas.UserUpdate, current_user: schemas.User = Depends(oauth2.get_current_user), 
                db: Session = Depends(PostgresDB.get_db)):
    existing_user = db.query(models.User).filter(
        ((models.User.email == update_user.email)
         & (models.User.id != current_user.id))
        | ((models.User.username == update_user.username) & (models.User.id != current_user.id))).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email and/or Username is/are already taken"
        )

    user = db.query(models.User).filter(
        models.User.id == current_user.id)
    user.update(update_user.model_dump(), synchronize_session=False)
    db.commit()

    return user.first()


@auth.get("/users/me", response_model=schemas.User)
async def get_user(current_user: schemas.User = Depends(oauth2.get_current_user)):
    return current_user


@auth.get("/download_private_key")
def download_private_key(current_user: schemas.User = Depends(oauth2.get_current_user)):
    private_key_path = os.path.join(PRIVATE_KEY_DIRECTORY, f"{current_user.username}_private_key.pem")
    
    if not os.path.exists(private_key_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Private key file not found"
        )

    return FileResponse(
        path=private_key_path,
        media_type="application/x-pem-file",
        filename="file_name_private_key.pem"
    )


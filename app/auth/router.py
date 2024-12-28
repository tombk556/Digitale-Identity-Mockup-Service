from app import models
from app.db import PostgresDB
from app.auth import oauth2, schemas
from app.auth.certificate import create_file

import os
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

auth = APIRouter(
    prefix="/auth",
    tags=["Authentication"])

PRIVATE_KEY_DIRECTORY = "/tmp/private_keys"

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
    
    user.password = oauth2.hash(user.password)
    new_user = models.User(**user.model_dump())
    

    download_url, public_key = create_file(str(new_user.id),
                                           new_user.name)
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


@auth.get("/download_private_key/{file_name}")
def download_private_key(file_name: str):
    
    PRIVATE_KEY_DIRECTORY = "/Users/tom/Documents/AWI Msc./3. Semester/Digitale Wirtschaft & Verwaltung/Fallbeispiel 3/Mockup/app/tmp"

    private_key_path = os.path.join(PRIVATE_KEY_DIRECTORY, f"{file_name}_private_key.pem")
    
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


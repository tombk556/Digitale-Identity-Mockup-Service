from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.auth import oauth2
from app.sign import schemas
from app.db import PostgresDB
from app import models
from app.config import settings

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import base64
import os

sign = APIRouter(
    prefix="/sign",
    tags=["Authentication"]
)

PRIVATE_KEY_DIRECTORY = settings.private_key_directory


@sign.post("/sign_message", response_model=schemas.SignResponse)
def sign_message(sign_req: schemas.SignRequest, current_user: schemas.User = Depends(oauth2.get_current_user),
):
    private_key_path = os.path.join(PRIVATE_KEY_DIRECTORY, f"{current_user.username}_private_key.pem")
    if not os.path.exists(private_key_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Private key file not found"
        )

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    signature = private_key.sign(
        sign_req.message.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    encoded_signature = base64.b64encode(signature).decode("utf-8")

    return schemas.SignResponse(signature=encoded_signature, message=sign_req.message)



@sign.post("/verify_signature", response_model=schemas.VerifyResponse)
def verify_signature(verify_req: schemas.VerifyRequest, db: Session = Depends(PostgresDB.get_db)):
    signer = db.query(models.User).filter(models.User.username == verify_req.username).first()
    if not signer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signer (user) does not exist"
        )

    if not signer.public_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signer has no public certificate"
        )

    try:
        cert_obj = x509.load_pem_x509_certificate(signer.public_key)
        public_key = cert_obj.public_key()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stored certificate is invalid or corrupted"
        )

    try:
        signature_bytes = base64.b64decode(verify_req.signature.encode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature is not valid base64"
        )

    try:
        public_key.verify(
            signature_bytes,
            verify_req.message.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return schemas.VerifyResponse(
            is_valid=True,
            detail="Signature is valid."
        )
    except Exception:
        return schemas.VerifyResponse(
            is_valid=False,
            detail="Signature is invalid."
        )

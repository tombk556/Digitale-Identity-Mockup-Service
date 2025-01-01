from pydantic import BaseModel, EmailStr
from uuid import UUID

class SignRequest(BaseModel):
    message: str

class SignResponse(BaseModel):
    signature: str

class VerifyRequest(BaseModel):
    message: str
    signature: str
    signer_id: str

class VerifyResponse(BaseModel):
    is_valid: bool
    detail: str
class User(BaseModel):
    id: UUID
    email: EmailStr
    username: str
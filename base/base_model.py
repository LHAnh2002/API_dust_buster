from pydantic import BaseModel


class Message(BaseModel):
    detail: int

class ChangePassword(BaseModel):
    old_password: str
    new_password: str
    enter_the_password: str

class AdminAvatar(BaseModel):
    image: str
    phonenumber: str

class AdminEmail(BaseModel):
    email: str

class OTPCreate(BaseModel):
    email: str
class OTPUserCreate(BaseModel):
    email: str
    name: str

class OTPVerify(BaseModel):
    email: str
    otp: str

class ResetPassword(BaseModel):
    email: str
    new_password: str

class ServiceCreate(BaseModel):
    id: str
    name: str
    icon: str
    note: str
    status: int

class ServiceUpdate(BaseModel):
    id: str
    status: int

class ServiceAllUpdate(BaseModel):
    id: str
    name: str
    icon: str
    note: str

class ServiceDurationCreate(BaseModel):
    time: int
    acreage: str
    room: str
    money: int
    status: int

class ServiceUpdateStatus(BaseModel):
    id: str
    status: int

class ServiceDurationUpdate(BaseModel):
    id: str
    time: int
    acreage: str
    room: str
    money: int

class UsersCreate(BaseModel):
    password: str
    phoneNumber: str
    email: str
    name: str
    sex: int
    datebirth: str
    referralCode:str

class RequestEmail(BaseModel):
    email: str


class ForgotPassword(BaseModel):
    email: str
    newPassword: str

class ReferralCode(BaseModel):
    referralCode: str
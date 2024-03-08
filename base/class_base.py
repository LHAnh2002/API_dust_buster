from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Admin(Base):
    __tablename__ = "admin"

    id = Column(String, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String)
    phonenumber = Column(String, nullable=False)
    name = Column(String, nullable=False)
    sex = Column(Integer, nullable=False)
    datebirth = Column(String, nullable=False)
    image = Column(String)
    permanent_address = Column(String, nullable=False)
    temporary_residence_address = Column(String, nullable=False)
    position = Column(String)
    joiningdate = Column(String, nullable=False)
    role = Column(Integer, nullable=False)
    status = Column(Integer, nullable=False)

class OTP(Base):
    __tablename__ = "otp"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String)
    name = Column(String)

class Promotion(Base):
    __tablename__ = "promotion"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    code = Column(String, nullable=False)
    image = Column(String, nullable=False)
    date = Column(String, nullable=False)
    content = Column(String, nullable=False)
    condition = Column(String, nullable=False)
    point = Column(Integer, nullable=False)

class Users(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    password = Column(String, nullable=False)
    phoneNumber = Column(String, nullable=False)
    email = Column(String)
    name = Column(String, nullable=False)
    image = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    g_points = Column(Integer, nullable=False)
    sex = Column(Integer, nullable=False)
    datebirth = Column(String, nullable=False)
    ban = Column(Integer, nullable=False)
    yourReferralCode = Column(String)
    referralCode = Column(String)


class CustomerPromotions(Base):
    __tablename__ = "customer_promotions"

    id = Column(String, primary_key=True)
    id_users = Column(String, ForeignKey('users.id'), nullable=False)
    id_promotion = Column(String, ForeignKey('promotion.id'), nullable=False)

class Partner(Base):
    __tablename__ = "partner"

    id = Column(String, primary_key=True)
    id_admin = Column(String, ForeignKey('admin.id'), nullable=False)
    email = Column(String)
    phonenumber = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String)
    name = Column(String, nullable=False)
    image = Column(String)
    datebirth = Column(String, nullable=False)
    address = Column(String, nullable=False)
    sex = Column(Integer, nullable=False)
    date = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    pet = Column(Integer, nullable=False)
    english = Column(Integer, nullable=False)
    ban = Column(Integer, nullable=False)
    censorship = Column(Integer, nullable=False)

class Payments(Base):
    __tablename__ = "payments"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)

class Invoice(Base):
    __tablename__ = "invoice"

    id = Column(String, primary_key=True)
    id_users = Column(String, ForeignKey('users.id'), nullable=False)
    id_partner = Column(String, ForeignKey('partner.id'), nullable=False)
    id_service = Column(String, nullable=False)  # Check if this should be a foreign key
    id_payments = Column(String, ForeignKey('payments.id'), nullable=False)
    english = Column(Integer)
    pet = Column(Integer)
    money = Column(Integer, nullable=False)
    tip = Column(Integer)
    order_status = Column(Integer, nullable=False)

class Service(Base):
    __tablename__ = "service"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    icon = Column(String, nullable=False)
    note = Column(String, nullable=False)
    status = Column(Integer)

class ServiceDuration(Base):
    __tablename__ = "service_duration"

    id = Column(String, primary_key=True)
    time = Column(Integer)
    acreage = Column(String)
    room = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    status = Column(Integer)

class OrderDetails(Base):
    __tablename__ = "order_details"

    id = Column(String, primary_key=True)
    invoice_id = Column(String, ForeignKey('invoice.id'), nullable=False)
    id_service_duration = Column(String, ForeignKey('service_duration.id'))
    repeat = Column(String)
    working_day = Column(String)
    end_date = Column(String)
    work_time = Column(String)
    now_start_working = Column(String)
    option = Column(String)
    extra_service = Column(String)
    note = Column(String)

class TotalSanitation(Base):
    __tablename__ = "total_sanitation"

    id = Column(String, primary_key=True)
    id_users = Column(String, ForeignKey('users.id'), nullable=False)
    note = Column(String, nullable=False)
    address = Column(String, nullable=False)

class AddServices(Base):
    __tablename__ = "add_services"

    id = Column(String, primary_key=True)
    icon = Column(String, nullable=False)
    name = Column(String, nullable=False)
    note = Column(String, nullable=False)
    money = Column(Integer, nullable=False)

class BusinessDuration(Base):
    __tablename__ = "business_duration"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)

class BusinessType(Base):
    __tablename__ = "business_type"

    id = Column(String, primary_key=True)
    icon = Column(String, nullable=False)
    name = Column(String, nullable=False)

class Evaluate(Base):
    __tablename__ = "evaluate"

    id = Column(String, primary_key=True)
    id_partner = Column(String, ForeignKey('partner.id'), nullable=False)
    star = Column(Integer, nullable=False)
    content = Column(String, nullable=False)
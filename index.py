from config.config import DATABASE_URL
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker, Session
from databases import Database
from base.class_base import OTP, Base, Admin, Service, ServiceDuration, Users
from base.base_model import ForgotPassword, RequestEmail, OTPUserCreate, UsersCreate, ServiceDurationUpdate, ServiceUpdateStatus, ServiceDurationCreate, ServiceAllUpdate, ServiceUpdate, Message, ChangePassword, AdminAvatar, OTPCreate, OTPVerify, ResetPassword, AdminEmail, ServiceCreate
from utils import convert_string, get_users, convert_date, get_select_service_duration, get_select_service, delete_otp_after_delay, random_id, create_jwt_token, verify_jwt_token, get_admin, oauth2_scheme, token_blacklist
from mail.otb_email import send_otp_email
from mail.cskh_email import send_cskh_email

def get_database():
    database = Database(DATABASE_URL)
    return database

# Kết nối đến cơ sở dữ liệu
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)

# Tạo đối tượng SessionLocal để tương tác với cơ sở dữ liệu
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
app = FastAPI(root_path="/api/v1")

#--------------------------------Admin-------------------------------------------------

# Đăng nhập
@app.post("/admin/login/")
async def login(form_data: dict, db: Session = Depends(get_database)):

    username = form_data["username"]
    password = form_data["password"]

    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, username)


    # Kiểm tra thông tin đăng nhập
    if admin is None or admin["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-1,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    #kiểm tra mật khẩu
    if admin is None or admin["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-2,
            headers={"WWW-Authenticate": "Bearer"},
        )
    #kiểm tra trạng thái
    if admin is None or admin["status"] != 1:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-3,
            headers={"WWW-Authenticate": "Bearer"},
        )


    # Tạo JWT token
    token_data = {"sub": admin["username"], "role": admin["role"]}
    token = create_jwt_token(token_data)

    # Trả về token
    return {"access_token": token, "token_type": "bearer"}

# Endpoint để xác minh token
@app.post("/verify-token/")
async def verify_token(token: str = Depends(verify_jwt_token)):
    # Nếu token hợp lệ, phương thức verify_jwt_token sẽ trả về payload của token
    # Trong trường hợp này, bạn có thể đơn giản trả về một phản hồi thành công hoặc dữ liệu từ payload nếu cần
    return {"message": "Token is valid", "payload": token}

# Endpoint đăng xuất
@app.post("/logout/", response_model=Message)
async def logout(token: str = Depends(oauth2_scheme)):
    # Thêm token vào danh sách đen khi đăng xuất
    token_blacklist.add(token)
    return Message(detail=0)

# Đổi mật khẩu người dùng
@app.put("/admin/change-password/", response_model=Message)
async def change_password(change_old_password: ChangePassword, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = await get_admin(db, current_user["sub"])
    update_new_password = ChangePassword(**change_old_password.dict())

    # Kiểm tra mật khẩu cũ
    if user["password"] != update_new_password.old_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=-1,
        )
    
    # Kiểm tra trùng mật khẩu
    if update_new_password.new_password != update_new_password.enter_the_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=-2,
        )
    
    update_query = update(Admin).where(Admin.id == user['id']).values(
            password=update_new_password.new_password)
    await db.execute(update_query)

    return Message(detail=0)

# Đổi avatar
@app.put("/admin/update-admin-avatar/", response_model=Message)
async def update_users_admin(update_user: AdminAvatar, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, current_user["sub"])
    update_avatar_admin = AdminAvatar(**update_user.dict())

    update_query = update(Admin).where(Admin.id == admin['id']).values(
        image=update_avatar_admin.image,
        phonenumber= update_avatar_admin.phonenumber
    )
    await db.execute(update_query)

    return Message( detail = 0)

# yêu cầu OTP
@app.post("/admin/request-otp/",response_model=Message)
async def request_otp(otp_data: OTPCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_database)):

    query = select(OTP).where(OTP.email == otp_data.email)
    otb_old = await db.fetch_one(query)
    
    if otb_old:
        delete_query = OTP.__table__.delete().where(OTP.email == otp_data.email)
        await db.execute(delete_query)
    
    query = select(Admin).where(Admin.email == otp_data.email)
    user = await db.fetch_one(query)
    if user:
        # Tạo và lưu OTP
        id = "OTB-"+ random_id()
        otp_code = str(random_id())

        new_otp_data = OTP(id=id, code=otp_code, **otp_data.dict())

        async with db.transaction():
            await db.execute(OTP.__table__.insert().values(
                id=new_otp_data.id,
                email=new_otp_data.email,
                code= otp_code,
            ))
        
        send_otp_email(new_otp_data.email, otp_code, user['name'])

        background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

        return Message(detail=0)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=-1)

@app.post("/request-otp-new-email/",response_model=Message)
async def request_otp_new_email(otp_data: OTPCreate, background_tasks: BackgroundTasks,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    
    user = await get_admin(db, current_user["sub"])
    query = select(OTP).where(OTP.email == otp_data.email)
    otb_old = await db.fetch_one(query)
    
    if otb_old:
        # Delete existing OTP data for the email
        delete_query = OTP.__table__.delete().where(OTP.email == otp_data.email)
        await db.execute(delete_query)
    
    id = "OTB-"+ random_id()
    otp_code = str(random_id())

    new_otp_data = OTP(id=id, code=otp_code, **otp_data.dict())

    async with db.transaction():
        await db.execute(OTP.__table__.insert().values(
            id=new_otp_data.id,
            email=new_otp_data.email,
            code= otp_code,
        ))
    
    send_otp_email(new_otp_data.email, otp_code, user['name'])

    background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

    return Message(detail=0)

# Đường dẫn để xác minh OTP
@app.post("/verify-otp/",response_model=Message)
async def verify_otp(otp_data: OTPVerify, db: Session = Depends(get_database)):

    query = select(OTP).where(OTP.email == otp_data.email)
    otp_old = await db.fetch_one(query)
    # import pdb
    # pdb.set_trace()
    if otp_old and otp_old['code'] == otp_data.otp:
        # OTP hợp lệ
        return Message(detail=0)
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=-1)

# Đường dẫn để xác minh OTP
@app.put("/admin/admin-update-email/",response_model=Message)
async def admin_update_email(admin_email: AdminEmail, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_admin(db, current_user["sub"])
    
    update_email = AdminEmail(**admin_email.dict())
    
    update_query = update(Admin).where(Admin.id == user['id']).values(
            email=update_email.email)
    await db.execute(update_query)

    return Message(detail=0)

@app.post("/admin/reset-password/",response_model=Message)
async def reset_password(form_data: ResetPassword ,db: Session = Depends(get_database),):

    otp_update_query = update(Admin).where(Admin.email == form_data.email).values(password=form_data.new_password)
    await db.execute(otp_update_query)

    return Message(detail=0)

# Thông tin admin
@app.get("/admin/select-admin-information/")
async def select_admin_information(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, current_user["sub"])
    
    # Trả về dữ liệu bảo vệ
    return {"admin_info": admin}


#---------------------------Quản lý tác vụ-------------------------------------------------

# Tạo dịch vụ
@app.post("/admin/create-service/", response_model=Message)
async def create_service(add_service: ServiceCreate, db: Session = Depends(get_database)):
    db_service = Service(**add_service.dict())
    
    async with db.transaction():
        await db.execute(Service.__table__.insert().values(
            id=db_service.id,
            name= db_service.name,
            icon= db_service.icon,
            note= db_service.note,
            status= db_service.status
        ))

    return Message(detail=0)

@app.get("/admin/select-service/")
async def select_service(db: Session = Depends(get_database)):

    db_select = await get_select_service(db)

    return {"service":db_select}

# Update dịch vụ
@app.put("/admin/update-service/",response_model=Message)
async def update_service(service_update: ServiceUpdate, db: Session = Depends(get_database)):
    
    _update = ServiceUpdate(**service_update.dict())
    
    update_query = update(Service).where(Service.id == _update.id).values(
            status=_update.status)
    await db.execute(update_query)

    return Message(detail=0)

# Sửa dịch vụ
@app.put("/admin/update-all-service/",response_model=Message)
async def update_all_service(service_update: ServiceAllUpdate, db: Session = Depends(get_database)):
    
    _update = ServiceAllUpdate(**service_update.dict())
    
    update_query = update(Service).where(Service.id == _update.id).values(
            name=_update.name,
            icon= _update.icon,
            note= _update.note
            )
    await db.execute(update_query)

    return Message(detail=0)

#---------------------------Quản lý Thời luọng-------------------------------------------------

# Tạo Thời lượng
@app.post("/admin/create-service-duration/", response_model=Message)
async def create_service_duration(add_service_duration: ServiceDurationCreate, db: Session = Depends(get_database)):
    
    id = "TL-" + str(random_id())
    db_service_duration = ServiceDuration(id=id, **add_service_duration.dict())
    
    async with db.transaction():
        await db.execute(ServiceDuration.__table__.insert().values(
            id=db_service_duration.id,
            time= db_service_duration.time,
            acreage= db_service_duration.acreage,
            room= db_service_duration.room,
            money= db_service_duration.money,
            status= db_service_duration.status
        ))

    return Message(detail=0)

@app.get("/admin/select-service-duration/")
async def select_service_duration(db: Session = Depends(get_database)):

    db_select = await get_select_service_duration(db)

    return {"service_duration":db_select}

# Update trạng thái thời lượng
@app.put("/admin/update-status-service-duration/",response_model=Message)
async def update_status_service_duration(service_duration_update: ServiceUpdateStatus, db: Session = Depends(get_database)):
    
    _update = ServiceDuration(**service_duration_update.dict())
    
    update_query = update(ServiceDuration).where(ServiceDuration.id == _update.id).values(
            status=_update.status)
    await db.execute(update_query)

    return Message(detail=0)

# Sửa thời lượng
@app.put("/admin/update-service-duration/",response_model=Message)
async def update_service_duration(service_duration_update: ServiceDurationUpdate, db: Session = Depends(get_database)):
    
    _update = ServiceDuration(**service_duration_update.dict())
    
    update_query = update(ServiceDuration).where(ServiceDuration.id == _update.id).values(
            time= _update.time,
            acreage= _update.acreage,
            room= _update.room,
            money= _update.money
            )
    await db.execute(update_query)

    return Message(detail=0)



# Đăng nhập người dùng
@app.post("/login-user/")
async def login_user(form_data: dict, db: Session = Depends(get_database)):

    email = form_data["email"]
    password = form_data["password"]

    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = await get_users(db, email)


    # Kiểm tra thông tin đăng nhập
    if user is None or user["email"] != email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-1,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    #kiểm tra mật khẩu
    if user is None or user["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-2,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user is None or user["ban"] != 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-3,
            headers={"WWW-Authenticate": "Bearer"},
        )


    # Tạo JWT token
    token_data = {"sub": user["email"], "id": user["id"]}
    token = create_jwt_token(token_data)

    # Trả về token
    return {"access_token": token, "token_type": "bearer"}
# yêu cầu OTP
@app.post("/request-otp-user/",response_model=Message)
async def request_otp_user(otp_data: OTPUserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_database)):
    
    name = ""
    if otp_data.name == "":
        query = select(Users).where(Users.email == otp_data.email)
        otb_old = await db.fetch_one(query)
        name = otb_old['name']
    query = select(OTP).where(OTP.email == otp_data.email)
    otb_old = await db.fetch_one(query)
    # Kiểm tra nếu otb_old không rỗng
    if otb_old:
        delete_query = OTP.__table__.delete().where(OTP.email == otp_data.email)
        await db.execute(delete_query)

    # Tạo và lưu OTP
    id = "OTB-"+ random_id()
    otp_code = str(random_id(6))

    new_otp_data = OTP(id=id, code=otp_code, **otp_data.dict())
    
    async with db.transaction():
        await db.execute(OTP.__table__.insert().values(
            id=new_otp_data.id,
            email=new_otp_data.email,
            code= otp_code,
            name=name
        ))
    send_otp_email(new_otp_data.email, otp_code, name)

    background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

    return Message(detail=0)

      
# Tạo tài khoản
@app.post("/create-users/", response_model=Message)
async def create_user(add_users: UsersCreate, db: Session = Depends(get_database)):
    
    db_user = Users(**add_users.dict())

    converted_name = convert_string(db_user.name)
    converted_date  = convert_date(db_user.datebirth)
    
    id = converted_name+converted_date
    async with db.transaction():
        await db.execute(Users.__table__.insert().values(
            id=id,
            password=db_user.password,
            phoneNumber=db_user.phoneNumber,
            email=db_user.email,
            name=db_user.name,
            image="",
            money=0,
            g_points=0,
            sex=db_user.sex,
            datebirth=db_user.datebirth,
            ban=0
        ))

    return Message(detail=0)

#kiểm tra email có tồn tại không
@app.post("/request-email/",response_model=Message)
async def request_email(otp_data: RequestEmail, db: Session = Depends(get_database)):

    query = select(Users).where(Users.email == otp_data.email)
    otb_old = await db.fetch_one(query)

    # Kiểm tra nếu otb_old không rỗng
    if otb_old:
        return Message(detail=0)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=-1)

# Quên mật khẩu người dùng
@app.put("/forgot-password/", response_model=Message)
async def forgot_password(update_forgot_password: ForgotPassword, db: Session = Depends(get_database)):
    
    update_query = update(Users).where(Users.email == update_forgot_password.email).values(
            password=update_forgot_password.newPassword)
    await db.execute(update_query)

    return Message(detail=0)

# # Hiển thị danh sách nhân viên còn làm việc
# @app.get("/dynamic_employee_display")
# async def dynamic_employee_display( current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
#     # Lấy thông tin người dùng hiện tại
#     user = await get_user_name(db, current_user["sub"])


#     # Lấy danh sách user có cùng id_set, loại bỏ user có id = id_set và status = 1
#     users_with_same_id_set = await get_dynamic_employee_display(db, user['id'])

#     return {"users": users_with_same_id_set}

# # Hiển thị danh sách nhân viên nghỉ việc
# @app.get("/select_employee_leave")
# async def select_employee_leave( current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
#     # Lấy thông tin người dùng hiện tại
#     user = await get_user_name(db, current_user["sub"])

#     # Lấy danh sách user có cùng id_set, loại bỏ user có id = id_set và status = 1
#     users_with_same_id_set = await get_select_employee_leave(db, user['id'])

#     return {"users_with_same_id_set": users_with_same_id_set}

# # Tìm kiếm nhân viên theo id hoặc tên
# @app.get("/search_employees_leave/")
# async def search_employees_leave(employees: Employees, current_user: dict = Depends(verify_jwt_token),
#                             db: Session = Depends(get_database)):
#     # Lấy thông tin người dùng hiện tại
#     user = await get_user_name(db, current_user["sub"])
#     db_user = User(**employees.dict())
#     # Kiểm tra quyền truy cập (chỉ admin mới có thể tìm kiếm nhân viên)
#     if user["role"] != 0:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail=-1,
#         )

#     # Tìm kiếm nhân viên theo id hoặc tên
#     employees = await search_employees_leave(db, db_user.id, user['id'])

#     return {"search_employees_leave": employees}

# # Tìm kiếm nhân viên theo id hoặc tên
# @app.get("/search_employees_display/")
# async def search_employees_display(employees: Employees ,current_user: dict = Depends(verify_jwt_token),
#                             db: Session = Depends(get_database)):
#     # Lấy thông tin người dùng hiện tại
#     user = await get_user_name(db, current_user["sub"])
#     db_user = User(**employees.dict())
#     # Kiểm tra quyền truy cập (chỉ admin mới có thể tìm kiếm nhân viên)
#     if user["role"] != 0:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail=-1,
#         )

#     # Tìm kiếm nhân viên theo id hoặc tên
#     employees = await search_employees_display(db, db_user.id, user['id'])

#     return {"search_employees_display": employees}



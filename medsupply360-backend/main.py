# main.py
import os
import io
import re
import csv
from datetime import datetime, timedelta, date
from typing import List, Optional

import databases
import sqlalchemy
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    status,
    Request,
    Response,
    File,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator
from prophet_model import router as prophet_router
from sqlalchemy.ext.asyncio import create_async_engine
from alerts import send_stock_alert
from models import Base
from models import User
from models import Sale

# -------------------------------------------------------------------
# 1. Load configuration, database, and metadata
# -------------------------------------------------------------------

from database_config import DATABASE_URL, DATABASE_URL1

# Create a Database instance (async)
database = databases.Database(DATABASE_URL)
metadata = Base.metadata

# SQLAlchemy Table definitions (Core)
medicines = sqlalchemy.Table(
    "Medicines",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String(255), nullable=False),
    sqlalchemy.Column("batch_number", sqlalchemy.String(100), nullable=False),
    sqlalchemy.Column("expiry_date", sqlalchemy.Date, nullable=False),
    sqlalchemy.Column("price", sqlalchemy.Numeric(10, 2), nullable=False),
    sqlalchemy.Column("quantity_in_stock", sqlalchemy.Integer, nullable=False),
    sqlalchemy.UniqueConstraint("name", "batch_number", name="uq_name_batch"),
)

sales_records = sqlalchemy.Table(
    "SalesRecords",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column(
        "medicine_id",
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey("Medicines.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sqlalchemy.Column("sale_date", sqlalchemy.Date, nullable=False),
    sqlalchemy.Column("quantity_sold", sqlalchemy.Integer, nullable=False),
)

# -------------------------------------------------------------------
# 2. JWT / Authentication configuration
# -------------------------------------------------------------------

# Read JWT settings from environment
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PROD")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic model for token responses
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Pydantic model for user
class UserBase(BaseModel):
    id: int
    username: str
    is_active: bool
    is_admin: bool
    class Config:
        orm_mode = True

class UserOut(UserBase):
    pass

class UserInDB(BaseModel):
    id: int
    username: str
    is_active: bool
    is_admin: bool
    hashed_password: str

class SaleCreate(BaseModel):
    medicine_id: int
    quantity: int


# Utility functions for hashing & verifying passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Fetch user from DB by username
async def get_user(username: str) -> Optional[UserInDB]:
    query = User.__table__.select().where(User.__table__.c.username == username)
    user_row = await database.fetch_one(query)
    if user_row:
        return UserInDB(
            id=user_row["id"],
            username=user_row["username"],
            hashed_password=user_row["hashed_password"],
            is_active=user_row["is_active"],
            is_admin=user_row["is_admin"]
        )
    return None

# Authenticate username & password
async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = await get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

# Create JWT access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15)) #expires in 15 mins
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await get_user(token_data.username)
    if not user:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

# Dependency to enforce authentication
async def get_current_active_user(current_user: UserBase = Depends(get_current_user)) -> UserBase:
    return current_user

# -------------------------------------------------------------------
# 3. FastAPI app instantiation & CORS middleware
# -------------------------------------------------------------------

app = FastAPI(title="MedSupply360 API")

# CORS: allow React frontend (adjust origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # <–– For development; specify your React origin in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# 4. Startup / Shutdown events
# -------------------------------------------------------------------

@app.on_event("startup")
async def startup():
    # Connect to database
    await database.connect()
    # Create tables if they don’t exist (only for dev)
    sync_engine = sqlalchemy.create_engine(DATABASE_URL1)
    metadata.create_all(sync_engine)



@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# -------------------------------------------------------------------
# 5. Auth Endpoints: token issuance & user creation
# -------------------------------------------------------------------

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Exchange username & password for a JWT access token.
    """
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# (Optional) Endpoint to create a new user (hashed password)
class UserCreate(BaseModel):
    username: str = Field(..., example="admin_user")
    password: str = Field(..., min_length=8, example="strongpassword123")
    is_active: bool = True
    is_admin: bool = False

@app.post("/users/", response_model=UserBase)
async def create_user(user_in: UserCreate):
    """
    Create a new user with hashed password. Only for dev/demo:
    In prod, lock this behind an admin-only endpoint.
    """
    hashed_password = get_password_hash(user_in.password)
    query = User.__table__.insert().values(
        username=user_in.username,
        hashed_password=hashed_password,
        is_admin=user_in.is_admin,
        is_active =user_in.is_active
    )
    try:
        user_id = await database.execute(query)
    except Exception:
        raise HTTPException(status_code=400, detail="Username already exists")
    return UserBase(id=user_id, username=user_in.username, is_active=user_in.is_active, is_admin=user_in.is_admin)

@app.get("/user/me", response_model=UserBase)
async def read_current_user(current_user: UserBase = Depends(get_current_active_user)):
    """
    get current authentification user's info
    """
    return current_user

# -------------------------------------------------------------------
# 6. Pydantic models for Medicines & Sales
# -------------------------------------------------------------------

class MedicineBase(BaseModel):
    name: str = Field(..., example="Paracetamol")
    batch_number: str = Field(..., example="B1234")
    expiry_date: date = Field(..., example="2025-12-31")
    price: float = Field(..., gt=0, example=9.99)
    quantity_in_stock: int = Field(..., ge=0, example=100)

    @validator("expiry_date")
    def expiry_must_be_future(cls, v: date) -> date:
        if v < date.today():
            raise ValueError("Expiry date must be in the future")
        return v

class MedicineCreate(MedicineBase):
    pass

class MedicineUpdate(BaseModel):
    price: Optional[float] = Field(None, gt=0)
    quantity_in_stock: Optional[int] = Field(None, ge=0)
    expiry_date: Optional[date] = None

    @validator("expiry_date")
    def expiry_must_be_future(cls, v: Optional[date]) -> Optional[date]:
        if v and v < date.today():
            raise ValueError("Expiry date must be in the future")
        return v

class Medicine(MedicineBase):
    id: int

    class Config:
        orm_mode = True

class SaleRecordCreate(BaseModel):
    medicine_id: int
    sale_date: date = Field(default_factory=date.today)
    quantity_sold: int = Field(..., gt=0)

class SaleRecord(BaseModel):
    id: int
    medicine_id: int
    sale_date: date
    quantity_sold: int

    class Config:
        orm_mode = True

# -------------------------------------------------------------------
# 7. Protected Medicine Endpoints (require valid token)
# -------------------------------------------------------------------

@app.post(
    "/medicines/",
    response_model=Medicine,
    dependencies=[Depends(get_current_active_user)],
)
async def add_medicine(
    med: MedicineCreate,
):
    """
    Add a new medicine. Requires valid JWT token.
    """
    query = medicines.insert().values(
        name=med.name,
        batch_number=med.batch_number,
        expiry_date=med.expiry_date,
        price=med.price,
        quantity_in_stock=med.quantity_in_stock,
    )
    try:
        medicine_id = await database.execute(query)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Medicine with this name & batch already exists",
        )
    return {**med.dict(), "id": medicine_id}

@app.get(
    "/medicines/",
    response_model=List[Medicine],
    dependencies=[Depends(get_current_active_user)],
)
async def list_medicines(skip: int = 0, limit: int = 50) -> List[Medicine]:
    """
    List medicines with pagination. Requires valid JWT token.
    """
    query = medicines.select().offset(skip).limit(limit)
    return await database.fetch_all(query)

@app.get(
    "/medicines/{medicine_id}",
    response_model=Medicine,
    dependencies=[Depends(get_current_active_user)],
)
async def get_medicine(medicine_id: int):
    """
    Retrieve a single medicine by ID. Requires valid JWT token.
    """
    query = medicines.select().where(medicines.c.id == medicine_id)
    med = await database.fetch_one(query)
    if not med:
        raise HTTPException(status_code=404, detail="Medicine not found")
    return med

@app.patch(
    "/medicines/{medicine_id}",
    response_model=Medicine,
    dependencies=[Depends(get_current_active_user)],
)
async def update_medicine(medicine_id: int, med_update: MedicineUpdate):
    """
    Update price, stock, or expiry date of a medicine. Requires valid JWT token.
    """
    existing = await database.fetch_one(
        medicines.select().where(medicines.c.id == medicine_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Medicine not found")
    update_data = med_update.dict(exclude_unset=True)
    query = (
        medicines.update()
        .where(medicines.c.id == medicine_id)
        .values(**update_data)
    )
    await database.execute(query)
    updated = await database.fetch_one(
        medicines.select().where(medicines.c.id == medicine_id)
    )
    return updated

# -------------------------------------------------------------------
# 8. Protected Sales Endpoint (require valid token)
# -------------------------------------------------------------------

@app.post(
    "/sales/",
    dependencies=[Depends(get_current_active_user)],
)
async def record_sales(sales: List[SaleRecordCreate]):
    """
    Record one or more sale transactions and decrement stock. Requires valid JWT token.
    Accepts a list of sales.
    """
    results = []

    for sale in sales:
        # 1. Validate medicine exists
        med = await database.fetch_one(
            medicines.select().where(medicines.c.id == sale.medicine_id)
        )
        if not med:
            raise HTTPException(status_code=404, detail=f"Medicine ID {sale.medicine_id} not found")

        # 2. Check stock availability
        if med["quantity_in_stock"] < sale.quantity_sold:
            raise HTTPException(
                status_code=400,
                detail=f"Not enough stock for medicine ID {sale.medicine_id}"
            )

        # 3. Insert sale record
        sale_query = sales_records.insert().values(
            medicine_id=sale.medicine_id,
            sale_date=sale.sale_date,
            quantity_sold=sale.quantity_sold,
        )
        sale_id = await database.execute(sale_query)

        # 4. Update stock
        new_quantity = med["quantity_in_stock"] - sale.quantity_sold
        update_query = (
            medicines.update()
            .where(medicines.c.id == sale.medicine_id)
            .values(quantity_in_stock=new_quantity)
        )
        await database.execute(update_query)

        results.append({**sale.dict(), "id": sale_id})

    return {"sales_recorded": results}

# -------------------------------------------------------------------
# 9. Inventory Status Endpoint (low-stock & expiry alerts)
# -------------------------------------------------------------------

@app.get(
    "/inventory/status/",
    dependencies=[Depends(get_current_active_user)],
)
async def inventory_status(
    low_stock_threshold: int = 10,
    expiry_within_days: int = 30,
    send_alerts: bool = False,
):
    """
    Returns two lists:
      - medicines low in stock (< low_stock_threshold)
      - medicines expiring within expiry_within_days
    """
    today = date.today()
    expiry_cutoff = today + timedelta(days=expiry_within_days)

    low_stock_query = medicines.select().where(
        medicines.c.quantity_in_stock < low_stock_threshold
    )
    expiring_soon_query = medicines.select().where(
        medicines.c.expiry_date <= expiry_cutoff
    )

    low_stock = await database.fetch_all(low_stock_query)
    expiring_soon = await database.fetch_all(expiring_soon_query)
    
    if send_alerts and low_stock:
        med_names = [med["name"] for med in low_stock]
        message = f"⚠️ Low stock alter for: {', '.join(med_names)}"
        send_stock_alert(message)

    return {
        "low_stock": low_stock,
        "expiring_soon": expiring_soon,
    }

# -------------------------------------------------------------------
# 9.5. Protected Endpoint: CSV Upload for Bulk Medicine Import
# -------------------------------------------------------------------

@app.post("/upload-medicines-csv/", dependencies=[Depends(get_current_active_user)])
async def upload_medicines_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are allowed.")

    content = await file.read()
    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        decoded = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(decoded))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid CSV encoding or structure")

    required_fields = {"name", "batch_number", "expiry_date", "price", "quantity_in_stock"}
    added = 0
    errors = []

    def escape_csv_formula(val: str) -> str:
        return "'" + val if val.startswith(("=", "+", "-", "@")) else val
    
    def clean_field(val: str) -> str:
        val = val.strip()
        val = re.sub(r"[^\x20-\x7E]+", "", val)  # Remove non-printable
        return "'" + val if val.startswith(("=", "+", "-", "@")) else val

    for i, row in enumerate(reader, start=1):
        try:
            if not required_fields.issubset(row.keys()):
                raise ValueError(f"Missing required fields in row {i}")

            name = escape_csv_formula(row["name"].strip())
            batch_number = escape_csv_formula(row["batch_number"].strip())
            expiry_date = datetime.strptime(row["expiry_date"].strip(), "%Y-%m-%d").date()
            if expiry_date < date.today():
                raise ValueError("Expiry date must be in the future")

            price = float(row["price"].strip())
            if price <= 0:
                raise ValueError("Price must be positive")

            quantity_in_stock = int(row["quantity_in_stock"].strip())
            if quantity_in_stock < 0:
                raise ValueError("Quantity cannot be negative")

            query = medicines.insert().values(
                name=name,
                batch_number=batch_number,
                expiry_date=expiry_date,
                price=price,
                quantity_in_stock=quantity_in_stock,
            )
            await database.execute(query)
            added += 1

        except Exception as e:
            errors.append(f"Row {i}: {str(e)}")

    return {
        "status": "complete",
        "records_added": added,
        "errors": errors,
    }


# -------------------------------------------------------------------
# 10. (Optional) Static Files / Health Check
# -------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """
    Simple health check endpoint.
    """
    return {"status": "OK", "timestamp": datetime.utcnow()}


app.include_router(prophet_router)

# -------------------------------------------------------------------
# 11. Notes on HTTPS (for prod)
# -------------------------------------------------------------------

"""
In production, don’t run with Uvicorn directly. Instead:
1. Use a proper ASGI server (e.g., Uvicorn or Hypercorn behind Nginx).
2. Terminate HTTPS at Nginx (or a load balancer), so that all incoming
   traffic is TLS-encrypted. Example Nginx snippet:

    server {
        listen 443 ssl;
        server_name api.yourdomain.com;

        ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

3. In your code, enforce HTTPS‐only cookies or headers as needed.
"""

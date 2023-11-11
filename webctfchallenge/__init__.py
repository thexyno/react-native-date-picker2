from ast import Dict
from datetime import datetime, timedelta
import os
from typing import Annotated
import typing

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from jose.constants import ALGORITHMS
from jose import backends
import uvicorn

def better_init(self, key, algorithm):
    if algorithm not in ALGORITHMS.HMAC:
        raise JWSError("hash_alg: %s is not a valid hash algorithm" % algorithm)
    self._algorithm = algorithm
    self._hash_alg = self.HASHES.get(algorithm)

    if isinstance(key, str):
        key = key.encode("utf-8")

    self.prepared_key = key

backends.native.HMACKey.__init__ = better_init

from jose import JWSError, JWTError, jwt

file_path = os.path.abspath(os.path.dirname(__file__))

# to get a string like this run:
# openssl rand -hex 32
PUBLIC_KEY = ""
PRIVATE_KEY = ""
with open(f'{file_path}/jwtRS256.key', encoding="utf-8") as f:
    PRIVATE_KEY = f.read()
with open(f'{file_path}/jwtRS256.key.pub', encoding="utf-8") as f:
    PUBLIC_KEY = f.read()
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2a$10$hjaNaJvz.RzRY5rL4ZcVMOQIKQu4j4do2VlR7bdYeO1N6tUwiZZzO",
        "disabled": False,
    },
    "flag": {
        "username": "flag",
        "full_name": os.environ.get("FLAG", "Laborctf{tbd}"),
        "email": "johndoe@example.com",
        "hashed_password": "",
        "disabled": False,
    },
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class Users(BaseModel):
    users: list[str]

class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
        title="LaborCTF web",
        description="password for johndoe is `sicher`")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    credentials_exception2 = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials (user unknown)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM, "HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError as error:
        print(f"JWTError: {error}")
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception2
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
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


@app.get("/", response_model=str)
def base():
    return "look at /docs"
@app.get("/users", response_model=Users)
def users():
    return { "users": [ "johndoe", "flag"] }
@app.get("/pubkey")
def pubkey(
):
    return {"key": PUBLIC_KEY}

@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

def main():
    import uvicorn
    uvicorn.run("webctfchallenge:app", host=os.environ.get("HOST","0.0.0.0"), port=int(os.environ.get("PORT","5000")), log_level="info")
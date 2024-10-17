from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pprint import pprint

from db import User
from db import SessionContext

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
    "stud@isu.ru": {
        "username": "stud@isu.ru",
        "full_name": "Alice Wonderson",
        "email": "stud@isu.ru",
        "hashed_password": "fakehashedmath!@",
        "disabled": False,
    },
}

# app = FastAPI(root_path='/api/v8')
app = FastAPI()

# origins = [
#     "http://localhost",
#     "https://logtalk.ru",
#     "http://logtalk.ru",
#     "https://localhost",
#     "http://localhost:8080",
# ]

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="oauth/token")

session_context = SessionContext(echo=True)

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str

def get_user(username: str = None, token: str = None):
    if token is not None:
        user = session_context.get_current_user(token)
    elif username is not None:
        user = session_context.get_user(username)
    print(user)
    return user
    # if username in db:
    #     user_dict = db[username]
    #     return UserInDB(**user_dict)

def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(token=token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/oauth/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    print(form_data.username)
    user = get_user(form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    # user_dict = user.as_dict()
    pwcheck = session_context.check_password(form_data.password, user)
    if not pwcheck:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    token = session_context.create_session(user)

    return {
        "access_token": token,
        "username": user.username,
        "token_type": "bearer",
        "scope": "public",
        "create_at": user.create_at
    }


@app.options("/api/v8/users/current")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user

@app.get("/api/v8/users/current")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user

@app.put("/api/v8/users/current")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: dict
):
    # UserInDB(username='stud@isu.ru', email='stud@isu.ru', full_name='Alice Wonderson', disabled=False, hashed_password='****')
    # {'user': {'extra_fields': {'data': {'course_variant': '',
    #                                     'digital_education_for_all': True,
    #                                     'marketing': True,
    #                                     'research': '0',
    #                                     'use_course_variant': False},
    #                            'namespace': 'programming-24'}},
    #  'user_field': {'first_name': 'Евгений',
    #                 'last_name': 'Черкашин',
    #                 'organizational_id': 'ISTU'}}

    pprint(current_user)
    pprint(data)
    return current_user


# --------------------------------------------------------------------------

@app.get("/api/1.0/test/hello/")
async def root():
    return {"message": "Hello World"}

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


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    sess, user = session_context.get_current_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return (sess, user)


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    sess, user = current_user
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/oauth/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    print(form_data.username)
    sess, user = get_user(form_data.username)
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
    return current_user[1]


def json_repr_user(
        user: User,
        show_user_fields:bool=False,
        extra_fields:str|None=None):
    d = user.as_dict()
    pprint(d)
    d["id"] = d["pk"]
    del d["pwhash"]
    if show_user_fields and d["first_name"] is not None:
        uf = {
            "first_name": d["first_name"],
            "last_name": d["last_name"],
            "html1": "",
            "organizational_id": d["organization"],
            "course_announcements": 0
        }
        d["user_field"] = uf
        for f in ["first_name", "last_name", "organization"]:
            del d[f]
    if extra_fields and "extra_fields" in d:
        d["extra_fields"] = d["extra"]["data"]
    d["extra"]

    pprint(d)
    return d


@app.get("/api/v8/users/current")
async def read_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
    show_user_fields: bool | None = False,
    extra_fields: str | None = None
):
    print(">>>>>", show_user_fields, extra_fields)
    return json_repr_user(current_user[1],
                          show_user_fields=show_user_fields,
                          extra_fields=extra_fields)


@app.put("/api/v8/users/current")
async def update_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: dict
):

    sess, user = current_user
    user_field = data["user_field"]
    user.first_name = user_field["first_name"]
    user.last_name = user_field["last_name"]
    user.organization = user_field["organizational_id"]

    user.extra = data["user"]["extra_fields"]
    session_context.update_user(current_user)

    pprint(user)
    pprint(data)
    return json_repr_user(user)


# --------------------------------------------------------------------------

@app.get("/api/1.0/test/hello/")
async def root():
    return {"message": "Hello World"}

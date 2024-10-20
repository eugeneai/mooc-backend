from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pprint import pprint

from db import User, WrongUserException
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


def get_user(username: str = None, token: str = None):
    if token is not None:
        user = session_context.get_current_user(token)
    elif username is not None:
        user = session_context.get_user(username, either=True)
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
    if extra_fields and "extra" in d and "extra_fields" in d["extra"]:
        d["extra_fields"] = d["extra"]["extra_fields"]
    del d["extra"]

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

    user.extra = user.extra["extra_fields"] = data["user"]["extra_fields"]
    session_context.update_user(current_user)

    pprint(user)
    pprint(data)
    return json_repr_user(user)


@app.post("/api/v8/users")
async def add_user(
    data: dict
):
    # {"user":
    #  {"email":"stud1@isu.ru",
    #   "password":"ыегв1",
    #   "password_confirmation":"ыегв1",
    #   "username":"e97ce51b-af57-448e-bb06-dd5fa86aac00"},
    #  "origin":"Python Programming MOOC 2024",
    #  "language":"fi"}

    user = data["user"]
    email = user["email"]
    password = user["password"]
    password_confirmation = user["password_confirmation"]
    username = user["username"]
    del data["user"]
    if password != password_confirmation:
        raise HTTPException(status_code=400, detail="Password and its confirmation do not match")
    try:
        sess, user = session_context.create_user(
            username=username,
            email=email,
            password=password,
            pk=username,
            extra={"origin": data})
    except WrongUserException as e:
        raise HTTPException(status_code=400, detail=str(e))

    token = session_context.create_session(user)
    return {
        "access_token": token,
        "username": user.username,
        "token_type": "bearer",
        "scope": "public",
        "create_at": user.create_at
    }


@app.get("/api/v8/org/{univ}/courses/{course_name}")
async def university_course(
    current_user: Annotated[User, Depends(get_current_active_user)],
    univ: str,
    course_name: str,
    request: Request
):
    u = str(request.url).split("/api/v8/")[0]+"/"
    material_url = u
    d = {
        "name": univ + "-" + course_name,
        "hide_after": None,
        "hidden": False,
        "cache_version": 2,
        "spreadsheet_key": None,
        "hidden_if_registered_after": None,
        "refreshed_at": "2024-05-30T14:51:47.976+03:00",
        "locked_exercise_points_visible": True,
        "paste_visibility": None,
        "formal_name": None,
        "certificate_downloadable": False,
        "certificate_unlock_spec": None,
        "organization_id": 13,
        "disabled_status": "enabled",
        "title": "PYTHON TVT24Eng",
        "description": "Introduction to programming with Python. Any TVT 24 group.\r\n\r\nYou can select this course instead of your group's course. Inform your teacher if you do!",
        "material_url": material_url, # "https://programming-24.mooc.fi/",
        "course_template_id": 511,
        "hide_submission_results": False,
        "external_scoreboard_url": None,
        "organization_slug": univ
    }
    return d


@app.get("/api/v8/org/{univ}")
async def university(
    univ: str,
):
    d = {
        "name": "Business College Helsinki",
        "information": "Tieto- ja viestintätekniikka",
        "slug": univ,
        "logo_path": "/rails/active_storage/representations/redirect/eyJfcmFpbHMiOnsiZGF0YSI6OCwicHVyIjoiYmxvYl9pZCJ9fQ==--9e3cb475cb115067465a2304a04d388fddb18d1c/eyJfcmFpbHMiOnsiZGF0YSI6eyJmb3JtYXQiOiJqcGciLCJyZXNpemVfdG9fZmlsbCI6WzEwMCxudWxsXX0sInB1ciI6InZhcmlhdGlvbiJ9fQ==--b34d03e0b131f4c14e9513df4f6090d7828cdc9d/BC-logo-viininpunainen-jpg.jpg",
        "pinned": False
    }
    return d



# --------------------------------------------------------------------------

@app.get("/api/1.0/test/hello/")
async def root():
    return {"message": "Hello World"}

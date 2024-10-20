from typing_extensions import Annotated

from sqlalchemy import (UniqueConstraint, ForeignKey)
from sqlalchemy import (String, Boolean, Uuid as SQL_UUID)
from sqlalchemy import JSON as SQL_JSON
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import declared_attr
from sqlalchemy.orm import Session
from uuid import UUID, uuid1 as uuid

from sqlalchemy_json import mutable_json_type

from sqlalchemy import (create_engine, select)
import bcrypt
import time
import base64

from sqlalchemy.exc import NoResultFound

CONN_STR = "postgresql+psycopg://mooc:mooc312@ktulhu/mooc"

str100 = Annotated[str, mapped_column(String(100), nullable=True)]
uuid_pk_t = Annotated[UUID, mapped_column(primary_key=True)]
user_fk_t = Annotated[UUID, mapped_column(ForeignKey("user_account.pk"), nullable=False)]
js_data = Annotated[dict, mapped_column(mutable_json_type(dbtype=SQL_JSON, nested=True), nullable=True)]


class Base(DeclarativeBase):
    type_annotation_map = {
        str100: String(100),
        uuid_pk_t: SQL_UUID,
        user_fk_t: SQL_UUID,
    }
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class User(Base):
    """Registered user data stored in SQL DB
    """
    __tablename__ = "user_account"

    pk: Mapped[uuid_pk_t]
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    pwhash: Mapped[str] = mapped_column(String(200), nullable=True)
    create_at: Mapped[int] = mapped_column(nullable = False)
    first_name: Mapped[str100]
    last_name: Mapped[str100]
    organization: Mapped[str100]
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    administrator: Mapped[bool] = mapped_column(Boolean, default=False)
    extra: Mapped[js_data]

    session: Mapped["UserSession"] = relationship(back_populates="user")


class UserSession(Base):
    """Stores user sessions. At least map token to User"""
    __tablename__ = "user_session"

    token: Mapped[uuid_pk_t]
    user_fk: Mapped[user_fk_t]
    user: Mapped["User"] = relationship(back_populates="session")


class WrongUserException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class SessionContext:
    def __init__(self, engine=None, echo=False):
        if engine is None:
            engine = create_engine(CONN_STR, echo=echo)
        self.engine = engine

    def get_user(self, username=None, email=None, either=False):
        if either:
            if username is not None:
                stmt = select(User).filter(User.username == username or User.email == username)
            else:
                raise ValueError("username must be set")
        else: # either == False, default
            if username is not None:
                stmt = select(User).filter(User.username == username)
            elif email is not None:
                stmt = select(User).filter(User.email == email)
            else:
                raise ValueError("either username or email must be set")

        session = self.session()
        try:
            user = session.scalars(stmt).one()
        except NoResultFound:
            return (None, None)
        return (session, user)

    def update_user(self, ctx):
        (sess, _) = ctx
        sess.commit()
        return ctx

    def get_current_user(self, token):
        s = self.session()
        try:
            stmt = select(UserSession).filter(UserSession.token == token)
            sess = s.scalars(stmt).one()
            user = sess.user
        except NoResultFound:
            return (None, None)
        return (s, user)

    def check_password(self, password: str, user: User):
        return bcrypt.checkpw(password.encode("utf-8"), user.pwhash.encode("utf-8"))

    def create_session(self, user: User):
        with self.session() as s:
            sess = UserSession(token=uuid(), user_fk=user.pk)
            s.add(sess)
            s.commit()
            token = sess.token
        return token

    def create_user(self, username, email, password, pk=None, extra=None):
        sess, user = self.get_user(email=email)
        if user is not None:
            raise WrongUserException("User already exists")
        hashpw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        sess = self.session()
        user = User(
            pk=UUID(pk),
            username=username,
            email=email,
            create_at=int(time.time()),
            pwhash=hashpw,
            administrator=False,
            extra = extra if extra is not None else None
        )
        sess.add(user)
        sess.commit()

        return (sess, user)


    def session(self):
        return Session(self.engine)


# session_context = SessionContext()

def create_db(echo=True):
    engine = create_engine(CONN_STR, echo=echo)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        admin = User(
            pk=UUID("1ba1aae5-4125-4dfe-a0bf-987e5c63ad4b"),
            username="admin",
            email="admin@example.com",
            create_at=int(time.time()),
            pwhash=bcrypt.hashpw("password".encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
            administrator=True
        )
        stud = User(
            pk=UUID("2d3c2416-8c7f-11ef-93f9-ef12b118bc6a"),
            username="stud@isu.ru",
            email="stud@isu.ru",
            create_at=int(time.time()),
            pwhash=b"$2b$12$U4nyzBm56pOgJ8xqnKQScOKsPZHSkTUX4iRehQoZaLKCY0lonFz8e".decode("utf-8")
        )
        session.add(admin)
        session.add(stud)
        session.commit()

#create_db()

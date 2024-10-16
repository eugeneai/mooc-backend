from typing_extensions import Annotated

from sqlalchemy import ( UniqueConstraint, ForeignKey )
from sqlalchemy import ( String, Uuid as SQL_UUID )
from sqlalchemy import JSON as SQL_JSON
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import declared_attr
from sqlalchemy.orm import Session
from uuid import UUID

from sqlalchemy_json import mutable_json_type

from sqlalchemy import create_engine
import bcrypt

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


class User(Base):
    """Registered user data stored in SQL DB
    """
    __tablename__ = "user_account"

    pk: Mapped[uuid_pk_t]
    alias: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    pwhash: Mapped[str] = mapped_column(String(200), nullable=True)
    firs_name: Mapped[str100]
    last_name: Mapped[str100]
    organization: Mapped[str100]
    extra: Mapped[js_data]

    session: Mapped["UserSession"] = relationship(back_populates="user")

class UserSession(Base):
    """Stores user sessions. At least map token to User"""
    __tablename__ = "user_session"

    token: Mapped[uuid_pk_t]
    user_fk: Mapped[user_fk_t]
    user: Mapped["User"] = relationship(back_populates="session")

ENGINE = create_engine(CONN_STR)

def create_db(echo=True):
    engine = create_engine(CONN_STR, echo=echo)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        admin = User(
            pk = UUID("1ba1aae5-4125-4dfe-a0bf-987e5c63ad4b"),
            alias = "admin",
            email = "admin@example.com",
            pwhash = bcrypt.hashpw(b"password", bcrypt.gensalt())
        )
        session.add(admin)
        session.commit()

create_db()

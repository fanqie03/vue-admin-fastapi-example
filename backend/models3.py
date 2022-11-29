import os
import re
import json
import time
import random
from enum import Enum, IntEnum
from datetime import datetime
from typing import Union, List, Dict, TypeVar, Generic, T
from datetime import timedelta
import logging
import string


from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Header, status
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select, Column, String


from faker import Faker


from passlib.apps import custom_app_context
from jose import JWTError, jwt, ExpiredSignatureError

from config import settings, logger

"""
========
数据操作
========
"""

fake = Faker(locale="zh-CN")

engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL,
    echo=True
)


def get_session():
    with Session(engine) as session:
        yield session

class UserRoleLink(SQLModel, table=True):
    __tablename__ = 'sys_users_roles'
    user_id: Optional[int] = Field(
        default=None, foreign_key="sys_user.user_id", primary_key=True
    )
    role_id: Optional[int] = Field(
        default=None, foreign_key="sys_role.role_id", primary_key=True
    )


class UserBase(SQLModel):
    user_id: int = Field(primary_key=True, description='用户id')
    dept_id: int
    username: str = Field(index=True, sa_column=Column(String(127)))
    nick_name: str
    gender: str
    phone: Optional[str] 
    email: Optional[str]
    avatar_name: Optional[str]
    avatar_path: Optional[str]
    password: str
    is_admin: bool
    enabled: int

    create_by: Optional[str]
    update_by: Optional[str]
    pwd_reset_time: datetime
    create_time: Optional[datetime] = Field(sa_column_kwargs=dict(default=datetime.now))
    update_time: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=datetime.now, default=datetime.now))


class User(UserBase, table=True):
    __tablename__ = 'sys_user'

    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRoleLink)
    



class RoleBase(SQLModel):
    role_id: int = Field(primary_key=True)
    name: Optional[str]
    level: Optional[str]
    description: Optional[str]
    data_scope: Optional[str]

    create_by: Optional[str]
    update_by: Optional[str]

    create_time: Optional[datetime] = Field(sa_column_kwargs=dict(default=datetime.now))
    update_time: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=datetime.now, default=datetime.now))

class RoleMenuLink(SQLModel, table=True):
    __tablename__ = 'sys_roles_menus'
    role_id: Optional[int] = Field(
        default=None, foreign_key="sys_role.role_id", primary_key=True
    )
    menu_id: Optional[int] = Field(
        default=None, foreign_key="sys_menu.menu_id", primary_key=True
    )


class Role(RoleBase, table=True):
    __tablename__ = 'sys_role'

    users: List[User] = Relationship(back_populates='roles', link_model=UserRoleLink)
    menus: List['Menu'] = Relationship(back_populates='roles', link_model=RoleMenuLink)


class MenuBase(SQLModel):
    menu_id: int = Field(primary_key=True)
    pid: Optional[int] = 0
    sub_count:Optional[int] = 0
    type: Optional[str]
    title: Optional[str]
    name: Optional[str]
    component: Optional[str]
    menu_sort: Optional[str]
    icon: Optional[str]
    path: Optional[str]
    i_frame: Optional[bool]
    cache: Optional[bool]
    hidden: Optional[bool]
    permission: Optional[str]

    create_by: Optional[str]
    update_by: Optional[str]

    create_time: Optional[datetime] = Field(sa_column_kwargs=dict(default=datetime.now))
    update_time: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=datetime.now, default=datetime.now))

class Menu(MenuBase, table=True):
    __tablename__ = 'sys_menu'

    roles: List[Role] = Relationship(back_populates='menus', link_model=RoleMenuLink)

class UserWithRoles(UserBase):
    roles: List[RoleBase]
    # 多级跳跃，需要自己整出来
    menus: List[MenuBase]

    # @classmethod
def create_by(user: User):
    menus = []
    roles = user.roles
    for role in user.roles:
        for menu in role.menus:
            menus.append(menu)
    
    user = user.dict()
    user['menus'] = menus
    user['roles'] = roles
    # user.menus = menus
    return user


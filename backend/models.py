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


from fastapi import Depends, FastAPI, HTTPException, status, APIRouter, Header, Body
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from faker import Faker
from pydantic import BaseSettings, validator, BaseModel
from pydantic.generics import GenericModel

from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref

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
    settings.SQLALCHEMY_DATABASE_URL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

def get_session():
    with SessionLocal() as session:
        yield session

Base = declarative_base()


class User(Base):
    __tablename__ = 'sys_user'
    user_id = Column(Integer, primary_key=True, comment='用户id')
    dept_id = Column(Integer, comment="部门id")
    username = Column(String(255), index=True, comment='用户名')
    nick_name = Column(String(255), comment='昵称')
    gender = Column(String(2), comment='性别')
    phone = Column(String(255), comment='手机号码')
    email = Column(String(255), comment='邮箱')
    avatar_name = Column(String(255), comment='头像地址')
    avatar_path = Column(String(255), comment='头像真实路径')
    password = Column(String(255), comment='密码')
    is_admin = Column(Boolean, default=False, comment='是否是admin账号')
    enabled = Column(Integer, comment='状态：1启动、0禁用')

    create_by = Column(String(255), comment='创建者')
    update_by = Column(String(255), comment='更新者')
    pwd_reset_time = Column(String(255), comment='修改密码时间')
    create_time = Column(DateTime, default=datetime.now, comment='创建日期')
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新日期')

    roles = relationship('Role', secondary="sys_users_roles", backref=backref('users'), lazy='dynamic')
    



class Role(Base):
    __tablename__ = 'sys_role'
    role_id = Column(Integer, primary_key=True, comment='ID')
    name = Column(String(255), comment="名称")
    level = Column(Integer, index=True, comment='角色级别')
    description = Column(String(255), comment='描述')
    data_scope = Column(String(2), comment='数据权限')

    create_by = Column(String(255), comment='创建者')
    update_by = Column(String(255), comment='更新者')
    create_time = Column(DateTime, default=datetime.now, comment='创建日期')
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新日期')

    menus = relationship('Menu', secondary="sys_roles_menus", backref=backref('roles'), lazy='dynamic')

class UserRole(Base):
    __tablename__ = 'sys_users_roles'
    user_id = Column(Integer, ForeignKey('sys_user.user_id'), primary_key=True,  comment='用户ID')
    role_id = Column(Integer, ForeignKey('sys_role.role_id'), primary_key=True,  comment='角色ID')


class Menu(Base):
    __tablename__ = 'sys_menu'
    menu_id = Column(Integer, primary_key=True, comment='ID')
    pid = Column(Integer, comment="上级菜单ID")
    sub_count = Column(Integer, comment="子菜单数目")
    type = Column(Integer, comment="菜单类型")
    title = Column(String(255), comment="菜单标题")
    name = Column(String(255), comment="组件名称")
    component = Column(Integer, index=True, comment='组件')
    munu_sort = Column(Integer, comment='排序')
    icon = Column(String(255), comment='图标')
    path = Column(String(255), comment='链接地址')
    i_frame = Column(Boolean, comment='是否外链')
    cache = Column(Boolean, comment='缓存')
    hidden = Column(Boolean, comment='隐藏')
    permission = Column(String(255), comment='权限')

    create_by = Column(String(255), comment='创建者')
    update_by = Column(String(255), comment='更新者')
    create_time = Column(DateTime, default=datetime.now, comment='创建日期')
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新日期')


class RoleMenu(Base):
    __tablename__ = 'sys_roles_menus'
    menu_id = Column(Integer, ForeignKey('sys_menu.menu_id'), primary_key=True, comment='菜单ID')
    role_id = Column(Integer, ForeignKey('sys_role.role_id'), primary_key=True, comment='角色ID')


class Article(Base):
    __tablename__ = 'article'
    id = Column(Integer, primary_key=True)
    title = Column(String(128), comment='标题|内容')
    status = Column(String(32), comment='状态')
    author = Column(String(32), comment='作者')
    display_time = Column(DateTime(), comment='创建时间')
    pageviews = Column(String(128), comment='浏览次数')

def create_table():
    logger.info("重置数据库 ...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    users = [('admin', '123456'), ('guest', '123456')]
    logger.info(f"创建账号 {users} ...")
    for username, password in users:
        user = User(username=username)
        user.hash_password(password)
        db.add(user)
    db.commit()
    logger.info(f"创建随机文章 {10} ...")
    items = []
    for i in range(10):
        items.append({
        'id': fake.unique.random_int(min=1, max=999),  # 随机且唯一
        'title': fake.text(),
        'status': random.choice(['published', 'draft', 'deleted']),
        'author': fake.name(),
        'display_time': fake.date_time(),
        'pageviews': fake.random_int(min=300, max=5000)
    })
    articles = [Article(**x) for x in items]
    db.add_all(articles)
    db.commit()
    

"""
========
数据操作
========
"""
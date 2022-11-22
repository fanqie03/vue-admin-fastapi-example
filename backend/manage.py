#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-11-22 20:53:54
# @Author  : mengfu188

import os
import re
import json
import time
from datetime import datetime
from typing import Union
from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status, APIRouter, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseSettings

from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from passlib.apps import custom_app_context
from jose import JWTError, jwt, ExpiredSignatureError
import uvicorn
from loguru import logger


basedir = os.path.abspath(os.path.dirname(__file__))


"""
配置相关
"""


class Settings(BaseSettings):
    app_title: str = "Awesome API"
    app_description: str = "Awesome API description"
    app_version: str = "0.0.1"
    admin_email: str  # 需要从环境变量指定
    items_per_user: int = 50
    # 数据库链接
    sqlalchemy_database_url: str = 'sqlite:///' + \
        os.path.join(basedir, 'data.sqlite')
    # sqlalchemy_database_url: str = "postgresql://user:password@postgresserver/db"
    #
    expire_minite: int = 30  # jwt超时时间
    secret_algorithm: str = 'HS256'  # jwt 加密算法
    # 加密密钥
    secret_key: str = '123456'
    # import secrets
    # secret_key: str = secrets.token_hex()

    api_name: str = 'manage:app'
    api_host: str = '0.0.0.0'
    api_port: int = 8000
    log_level: str = 'debug'

    class Config:  # 可以使用.env覆盖本地文件
        env_file = ".env"


settings = Settings()
# print(settings)

"""
配置相关
"""


"""
========
数据操作
========
"""

engine = create_engine(
    settings.sqlalchemy_database_url, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password = Column(String(128))

    # 密码加密
    def hash_password(self, password):
        self.password = custom_app_context.hash(password)

    # 密码解析
    def verify_password(self, password):
        return custom_app_context.verify(password, self.password)

    def create_access_token(self, data: dict = {}, expire_minite: Union[timedelta, None] = settings.expire_minite):
        to_encode = data.copy()
        expire = time.time() + expire_minite * 60
        to_encode.update({"exp": expire, "sub": str(self.id)}
                         )  # 加入用户名和超时时间  sub必须是字符串
        encoded_jwt = jwt.encode(
            to_encode, settings.secret_key, algorithm=settings.secret_algorithm)
        return encoded_jwt

    @classmethod
    def get_user(cls, x_token: str = Header()):
        """HTTP headers 是大小写不敏感的"""
        user_id = cls.get_user_id(x_token)
        return db.query(cls).filter(cls.id == user_id).first()

    @classmethod
    def get_user_id(cls, x_token: str = Header()):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
        print(x_token)
        try:
            payload = jwt.decode(x_token, settings.secret_key,
                                 algorithms=settings.secret_algorithm)
            print(payload)
            user_id: str = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="找不到user_id"
                )
            print(type(payload.get('exp')))
            if payload.get('exp') - time.time() <= 0:  # 超时
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,  # 重新登陆
                    detail="超时,请重新登陆"
                )
        except ExpiredSignatureError as e:
            logger.exception('jwt解析的时候如果令牌超会自动抛出异常,使用exp关键字')
            raise e
        except JWTError:
            logger.exception("解析失败")
            raise credentials_exception
        return user_id

    @classmethod
    def login(cls, username, password) -> Union['User', None]:
        user = db.query(cls).filter(cls.username == username).first()
        if user == None:  # 没有该用户
            return
        if user.verify_password(password):  # 密码验证成功
            return user
        return  # 密码验证失败


def create_table():
    Base.metadata.create_all(bind=engine)


"""
========
数据操作
========
"""

"""
fastapi 相关
"""
app = FastAPI(
    title=settings.app_title,
    version=settings.app_version,
    description=settings.app_description,
)
# app = FastAPI(root_path="/api/v1")

# '*' 是通配符，让本服务器所有的 URL 都允许跨域请求
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

user_router = APIRouter(
    prefix='/user', 
    tags=['user'],
    # dependencies=[Depends(get_token_header)],  # 可以让每个api都会需要经过这个检查
)

"""
错误处理
"""

# @app.exception_handler(ExpiredSignatureError)
# async def validation_exception_handler(request, exc):
#     return RedirectResponse(app.url_path_for('login'))

"""
错误处理
"""


@user_router.post('/login')
def login(username: str = Body(), password: str = Body()):
    user = User.login(username, password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="账号或密码错误"
        )
    else:
        access_token = user.create_access_token()
        return {"token": access_token, "msg": '登陆成功'}


@user_router.post('/register')
def register(username: str, password: str):
    user = User(username=username)
    user.hash_password(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {'msg': "注册成功"}


@user_router.post('/get_user_id')
def get_user_id(user_id: str = Depends(User.get_user_id)):
    return user_id

@user_router.get('/info')
def info(user_id: str = Depends(User.get_user_id)):  # 暂时不做角色,保留下来
    return {
        'roles': ['admin'],
        'introduction': 'I am a super administrator',
        'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
        'name': 'Super Admin'
    }

@user_router.post('/setpwd')
def set_auth_pwd(new_password: str, user: str = Depends(User.get_user)):
    # 疑问,修改成功后如何让旧的jwt失效(用户重新登陆),再就是怎么实现强制登出
    user.hash_password(new_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {'msg': "修改成功,请重新登陆"}


# 需要在定义api后,进行调用才会加入到app中
app.include_router(user_router)

if __name__ == '__main__':
    create_table()

    uvicorn.run(
        settings.api_name,   # 需要使用字符串模块名才能reload
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level,
        reload=True,
    )

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-11-22 20:53:54
# @Author  : mengfu188

import os
import re
import json
import time
import random
from datetime import datetime
from typing import Union, List
from datetime import timedelta
import logging

from fastapi import Depends, FastAPI, HTTPException, status, APIRouter, Header, Body
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseSettings, validator

from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from passlib.apps import custom_app_context
from jose import JWTError, jwt, ExpiredSignatureError
import uvicorn
from faker import Faker


basedir = os.path.abspath(os.path.dirname(__file__))
logger = logging.getLogger("uvicorn.access")

"""
配置相关
"""


class Settings(BaseSettings):
    APP_TITLE: str = "Awesome API"
    APP_DESCRIPTION: str = "Awesome API description"
    APP_VERSION: str = "0.0.1"
    ADMIN_EMAIL: str  # 需要从环境变量指定

    @validator('ADMIN_EMAIL')
    def test_validator(cls, v):
        return v

    ITEMS_PER_USER: int = 50
    # 数据库链接
    SQLALCHEMY_DATABASE_URL: str = 'sqlite:///' + \
        os.path.join(basedir, 'data.sqlite')
    # SQLALCHEMY_DATABASE_URL: str = "postgresql://user:password@postgresserver/db"
    #
    EXPIRE_MINITE: float = 10  # jwt超时时间
    SECRET_ALGORITHM: str = 'HS256'  # jwt 加密算法
    # 加密密钥
    SECRET_KEY: str = '123456'
    # import secrets
    # SECRET_KEY: str = secrets.token_hex()

    # 这个要如何处理呢
    # 接受 export CORS_ORIGINS='["example.com", "example2.com"]'
    CORS_ORIGINS: List[str] = ['*']
    CORS_METHODS: List[str] = ['*']
    CORS_HEADERS: List[str] = ['*']

    API_NAME: str = 'manage:app'
    API_HOST: str = '0.0.0.0'
    API_PORT: int = 8000
    # 可以使用 export API_RELOAD=False
    # a str which when converted to lower case is one of 
    # '0', 'off', 'f', 'false', 'n', 'no', '1', 'on', 't', 'true', 'y', 'yes'
    API_RELOAD: bool = True
    LOG_LEVEL: str = 'debug'

    class Config:  # 可以使用.env覆盖本地文件
        # env_prefix = 'my_prefix_'  # defaults to no prefix, i.e. ""
        env_file = ".env"
        # case_sensitive = True # 大小写敏感


settings = Settings()

"""
配置相关
"""


"""
========
数据操作
========
"""

fake = Faker(locale="zh-CN")

engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
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

    def create_access_token(self, data: dict = {}, EXPIRE_MINITE: Union[timedelta, None] = settings.EXPIRE_MINITE):
        to_encode = data.copy()
        expire = time.time() + EXPIRE_MINITE * 60
        to_encode.update({"exp": expire, "sub": str(self.id)}
                         )  # 加入用户名和超时时间  sub必须是字符串
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.SECRET_ALGORITHM)
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
        try:
            payload = jwt.decode(x_token, settings.SECRET_KEY,
                                 algorithms=settings.SECRET_ALGORITHM)
            user_id: str = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="找不到user_id"
                )
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

    users = [('admin', '111111'), ('guest', '111111')]
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

"""
fastapi 相关
"""
app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    # 禁用openapi和redoc
    # openapi_url=None,
    # docs_url=None,
    # redoc_url=None,
)
# app = FastAPI(root_path="/api/v1")

# '*' 是通配符，让本服务器所有的 URL 都允许跨域请求
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.CORS_METHODS,
    allow_headers=settings.CORS_HEADERS,
)

user_router = APIRouter(
    prefix='/user', 
    tags=['user'],
    # dependencies=[Depends(get_token_header)],  # 可以让每个api都会需要经过这个检查
)
table_router = APIRouter(
    prefix='/table',
    tags=['table'],
)
api_router = APIRouter(
    prefix='/api',
)

@app.on_event("startup")
async def startup_event():
    """日志配置 参考 https://www.51cto.com/article/707542.html"""
    logger = logging.getLogger("uvicorn.access")
    handler = logging.handlers.RotatingFileHandler("log/api.log",mode="a",maxBytes = 5*1024*1024, backupCount = 3, encoding='utf-8')
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

"""
错误处理
"""

@app.exception_handler(ExpiredSignatureError)
async def validation_exception_handler(request, exc):
    return JSONResponse({'message':"令牌超时，请重新登陆", 'code': 50014}, status_code=200)  # 自定义状态码 50014 表示登陆超时

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
        return {"token": access_token, "message": '登陆成功'}


@user_router.post('/register')
def register(username: str, password: str):
    user = User(username=username)
    user.hash_password(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {'message': "注册成功"}


@user_router.post('/get_user_id')
def get_user_id(user_id: str = Depends(User.get_user_id)):
    return user_id

@user_router.get('/info',dependencies=[])
def info(user_id: str = Depends(User.get_user_id)):  # 暂时不做角色,保留下来
    return {
        'roles': ['admin'],
        'introduction': 'I am a super administrator',
        'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
        'name': 'Super Admin'
    }

@user_router.post('/logout')
def logout():  # 暂时不做角色,保留下来
    return f"success"

@user_router.post('/setpwd')
def set_auth_pwd(new_password: str, user: str = Depends(User.get_user)):
    # 疑问,修改成功后如何让旧的jwt失效(用户重新登陆),再就是怎么实现强制登出
    user.hash_password(new_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {'message': "修改成功,请重新登陆"}

@table_router.get('/list')
def table_list():
    items = db.query(Article).all()
    return {'items': items}

@app.get('/')
def index():  # 将首页重定向到admin后台
    return RedirectResponse('/admin/index.html')


app.mount("/admin", StaticFiles(directory="admin"), name="admin")

# 需要在定义api后,进行调用才会加入到app中
api_router.include_router(user_router)
api_router.include_router(table_router)
app.include_router(api_router)

if __name__ == '__main__':
    create_table()

    uvicorn.run(
        settings.API_NAME,   # 需要使用字符串模块名才能reload
        host=settings.API_HOST,
        port=settings.API_PORT,
        LOG_LEVEL=settings.LOG_LEVEL,
        reload=settings.API_RELOAD,
    )

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-11-22 20:53:54
# @Author  : mengfu188

import os
import re
import json
import time
import random
from enum import Enum, IntEnum
from datetime import datetime
from typing import Union, List, Dict, TypeVar, Generic, T, Optional
from datetime import timedelta
import logging

from fastapi import Depends, FastAPI, HTTPException, status, APIRouter, Header, Body, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseSettings, validator, BaseModel
from pydantic.generics import GenericModel

# from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker

from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select, Column, String

from passlib.apps import custom_app_context
from jose import JWTError, jwt, ExpiredSignatureError
import uvicorn
from faker import Faker
from loguru import logger


basedir = os.path.abspath(os.path.dirname(__file__))
logger.add('log/loguru.log', rotation='1 MB', compression='zip')  # 滚动大日志

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
    settings.SQLALCHEMY_DATABASE_URL,
    echo=True
)


def get_session() -> Session:
    with Session(engine) as session:
        yield session



class User(SQLModel, table=True):
    __tablename__ = 'sys_user'
    __table_args__ = {'extend_existing': True}
    id: Optional[int] = Field(primary_key=True)
    username:str = Field(index=True, sa_column=Column(String(127)))
    password: str


class Article(SQLModel, table=True):
    __tablename__ = 'article'
    __table_args__ = {'extend_existing': True}
    id:int = Field(primary_key=True)
    title:str
    status:str
    author:str
    display_time:datetime
    pageviews:int

def create_table():
    logger.info("重置数据库 ...")
    SQLModel.metadata.drop_all(bind=engine)
    SQLModel.metadata.create_all(bind=engine)

    with Session(engine) as session:
        users = [('admin', '111111'), ('guest', '111111')]
        logger.info(f"创建账号 {users} ...")
        for username, password in users:
            user = User(username=username)
            user.password = Auth.hash_password(password)
            session.add(user)
        session.commit()
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
        session.add_all(articles)
        session.commit()


class Auth:

    # 密码加密
    @staticmethod
    def hash_password(password):
        return custom_app_context.hash(password)

    # 密码解析
    @staticmethod
    def verify_password(user, password):
        return custom_app_context.verify(password, user.password)

    @staticmethod
    def create_access_token(user, data: dict = {}, EXPIRE_MINITE: Union[timedelta, None] = settings.EXPIRE_MINITE):
        to_encode = data.copy()
        expire = time.time() + EXPIRE_MINITE * 60
        to_encode.update({"exp": expire, "sub": str(user.id)}
                         )  # 加入用户名和超时时间  sub必须是字符串
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.SECRET_ALGORITHM)
        return encoded_jwt


    """
    deps
    """


    @staticmethod
    def get_user(session:Session = Depends(get_session), x_token: str = Header()):
        """HTTP headers 是大小写不敏感的"""
        user_id = Auth.get_user_id(x_token)
        return session.get(User, user_id)

    @staticmethod
    def get_user_id(x_token: str = Header()):
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

    @staticmethod
    def login(session: Session = Depends(get_session), username: str = Body(), password: str = Body()) -> Union['User', None]:
        user = session.exec(select(User).where(User.username == username)).first()
        if user == None:  # 没有该用户
            return
        if Auth.verify_password(user, password):  # 密码验证成功
            return user
        return  # 密码验证失败


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
    handler = logging.handlers.RotatingFileHandler("log/uvicorn.log",mode="a",maxBytes = 5*1024*1024, backupCount = 3, encoding='utf-8')
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)



"""
schema
"""

DataT = TypeVar('DataT')



class CodeEnum(IntEnum):
    """
    自定义状态码
    20000 成功
    50014 表示令牌超时，需要重新登陆
    """
    success = 20000  
    token_expire = 50014


class SingleResponse(GenericModel, Generic[DataT]):
    code: CodeEnum = CodeEnum.success
    message: str = ''
    data: Union[DataT, None]


class ListResponse(GenericModel, Generic[DataT]):
    code: int = 20000
    message: str = ''
    page: int = 0
    count: int = 0
    data: List[DataT]




class Token(SQLModel):
    token: str


class TableItem(SQLModel):
    id: int
    title: str 
    status: str 
    author: str 
    display_time: datetime 
    pageviews: int 
    

"""
schema
"""

"""
错误处理
"""

@app.exception_handler(ExpiredSignatureError)
async def validation_exception_handler(request, exc):
    return {'message':"令牌超时，请重新登陆", 'code': CodeEnum.token_expire}

"""
错误处理
"""


@user_router.post('/login')
def login(user: Optional[User] = Depends(Auth.login)):
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="账号或密码错误"
        )
    else:
        access_token = Auth.create_access_token(user)
        return {'data': {'token': access_token}, 'message': '登陆成功'}



# @user_router.post('/register', response_model=SingleResponse)
# def register(username: str, password: str):
#     user = User(username=username)
#     user.password = Auth.hash_password(password)
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#     return {'message': "注册成功"}


@user_router.post('/get_user_id')
def get_user_id(user_id: str = Depends(Auth.get_user_id)):
    return user_id

@user_router.get('/info')
def info(user_id: str = Depends(Auth.get_user_id)):  # 暂时不做角色,保留下来
    return {
        'roles': ['admin'],
        'introduction': 'I am a super administrator',
        'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
        'name': 'Super Admin'
    }

@user_router.post('/logout', response_model=SingleResponse)
def logout():  # 暂时不做角色,保留下来
    return {}

# @user_router.post('/setpwd')
# def set_auth_pwd(new_password: str, user: str = Depends(Auth.get_user)):
#     # 疑问,修改成功后如何让旧的jwt失效(用户重新登陆),再就是怎么实现强制登出
#     user.hash_password(new_password)
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#     return {'message': "修改成功,请重新登陆"}

@table_router.get('/list', response_model=ListResponse[TableItem])
def table_list(*, session: Session = Depends(get_session), limit: int=Query(default=10, le=20), offset:int=Query(default=0)):
    items = session.exec(select(Article).limit(limit).offset(offset)).all()
    return {'data': items, 'count': len(items)}

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
        log_level=settings.LOG_LEVEL,
        reload=settings.API_RELOAD,
    )

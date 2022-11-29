
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
from models3 import User, get_session

class Auth:
    """认证相关的操作"""

    
    # 密码加密
    @staticmethod
    def hash_password(user, password):
        user.password = custom_app_context.hash(password)

    # 密码解析
    @staticmethod
    def verify_password(user, password):
        return custom_app_context.verify(password, user.password)

    @staticmethod
    def create_access_token(user, data: dict = {}, EXPIRE_MINITE: Union[timedelta, None] = settings.EXPIRE_MINITE):
        to_encode = data.copy()
        expire = time.time() + EXPIRE_MINITE * 60
        to_encode.update({"exp": expire, "sub": str(user.user_id)}
                         )  # 加入用户名和超时时间  sub必须是字符串
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.SECRET_ALGORITHM)
        return encoded_jwt



    """deps部分"""


    @staticmethod
    def get_user(session = Depends(get_session), x_token: str = Header()):
        """HTTP headers 是大小写不敏感的"""
        user_id = Auth.get_user_id(x_token)
        return session.query(User).filter(User.id == user_id).first()

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
    def login(*, session = Depends(get_session), username = Body(), password = Body()) -> Union['User', None]:
        user = session.query(User).filter(User.username == username).first()
        if user == None:  # 没有该用户
            return
        if Auth.verify_password(user, password):  # 密码验证成功
            return user
        return  # 密码验证失败

    # @staticmethod
    # def get_user_info()
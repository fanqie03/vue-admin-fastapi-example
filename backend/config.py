import logging
import os
from typing import List
from enum import IntEnum

from pydantic import BaseSettings, validator, BaseModel
from loguru import logger


logger.add('log/api.log', rotation='1 MB', compression='zip')  # 滚动大日志


basedir = os.path.abspath(os.path.dirname(__file__))


# logger = logging.getLogger("uvicorn.access")

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
    SQLALCHEMY_DATABASE_URL: str = 'mysql+pymysql://root:root@127.0.0.1:3306/eladmin?charset=utf8mb4'
    # SQLALCHEMY_DATABASE_URL: str = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
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
    # '0', 'off', 'f', 'False', 'n', 'no', '1', 'on', 't', 'True', 'y', 'yes'
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


class CodeEnum(IntEnum):
    """
    自定义状态码
    20000 成功
    50014 表示令牌超时，需要重新登陆
    """
    success = 20000  
    token_expire = 50014
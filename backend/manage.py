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
from typing import Union, List, Dict, TypeVar, Generic, T
from datetime import timedelta
import logging
import string

from fastapi import Depends, FastAPI, HTTPException, status, APIRouter, Header, Body
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseSettings, validator, BaseModel
from pydantic.generics import GenericModel

from sqlmodel import Session

from passlib.apps import custom_app_context
from jose import JWTError, jwt, ExpiredSignatureError
import uvicorn

from config import settings, logger, CodeEnum
from models import User, get_session
from crud import Auth



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


@app.middleware("http")
async def log_requests(request, call_next):
    idem = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    # logger.info(f"rid={idem} start request path={request.url.path}")
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    formatted_process_time = '{0:.2f}'.format(process_time)
    logger.info(f"request path={request.url.path} rid={idem} completed_in={formatted_process_time}ms status_code={response.status_code}")
    
    return response


# @app.on_event("startup")
# async def startup_event():
#     """日志配置 参考 https://www.51cto.com/article/707542.html"""
#     logger = logging.getLogger("uvicorn.access")
#     handler = logging.handlers.RotatingFileHandler("log/api.log",mode="a",maxBytes = 5*1024*1024, backupCount = 3, encoding='utf-8')
#     handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
#     logger.addHandler(handler)



"""
schema
"""

DataT = TypeVar('DataT')





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




class Token(BaseModel):
    token: str


class TableItem(BaseModel):
    id: int
    title: str 
    status: str 
    author: str 
    display_time: datetime 
    pageviews: int 
    
    class Config:
        orm_mode = True

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

"""
eladmin
"""

def get_token(authorization: str = Header()):
    logger.info(f"标题头部是{authorization}")
    return authorization


auth_router = APIRouter(prefix="/auth", tags=['auth'])

@auth_router.delete('/logout')
def auth_logout(token: str = Depends(get_token)):
    logger.info(f"登出 是{token}")
    """登出"""

@auth_router.get('/info')
def auth_info():
    """获取个人详细信息（个人中心）"""

@auth_router.get('/code')
def auth_code():
    """获取验证码"""

@auth_router.post('/login')
def auth_login(user: User = Depends(Auth.login)):
    """
    username 用户名
    password 密码
    code 验证码
    uuid 应该记得是验证码对应的答案

    返回token
    ```json
    {
        "token": "Bearer eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiI0NmI0MjNkMDA1YjE0ZjJlOTc1YThlYTc3MWQ0ZmE3NCIsInVzZXIiOiJhZG1pbiIsInN1YiI6ImFkbWluIn0.0OQat62mTLi8U3h3m2yvjnlfE0VSDB8y0yZVwAeW5YueXBPe9kzDtjDLaOAcJzxDANLCfdjA0cm4K4v0fobbaQ"
    }
    ```
    """
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="账号或密码错误"
        )
    else:
        access_token = Auth.create_access_token(user)
        return {'token': access_token}


menus_router = APIRouter(prefix='/menus', tags=['menus'])

@menus_router.get('/build')
def menus_build():
    """获取菜单栏
    ```json
    [
        {
            "alwaysShow": True,
            "children": [
                {
                    "component": "system/user/index",
                    "hidden": False,
                    "meta": {
                        "icon": "peoples",
                        "noCache": True,
                        "title": "用户管理"
                    },
                    "name": "User",
                    "path": "user"
                },
                {
                    "component": "system/role/index",
                    "hidden": False,
                    "meta": {
                        "icon": "role",
                        "noCache": True,
                        "title": "角色管理"
                    },
                    "name": "Role",
                    "path": "role"
                },
                {
                    "component": "system/menu/index",
                    "hidden": False,
                    "meta": {
                        "icon": "menu",
                        "noCache": True,
                        "title": "菜单管理"
                    },
                    "name": "Menu",
                    "path": "menu"
                },
                {
                    "component": "system/dept/index",
                    "hidden": False,
                    "meta": {
                        "icon": "dept",
                        "noCache": True,
                        "title": "部门管理"
                    },
                    "name": "Dept",
                    "path": "dept"
                },
                {
                    "component": "system/job/index",
                    "hidden": False,
                    "meta": {
                        "icon": "Steve-Jobs",
                        "noCache": True,
                        "title": "岗位管理"
                    },
                    "name": "Job",
                    "path": "job"
                },
                {
                    "component": "system/dict/index",
                    "hidden": False,
                    "meta": {
                        "icon": "dictionary",
                        "noCache": True,
                        "title": "字典管理"
                    },
                    "name": "Dict",
                    "path": "dict"
                },
                {
                    "component": "system/timing/index",
                    "hidden": False,
                    "meta": {
                        "icon": "timing",
                        "noCache": True,
                        "title": "任务调度"
                    },
                    "name": "Timing",
                    "path": "timing"
                }
            ],
            "component": "Layout",
            "hidden": False,
            "meta": {
                "icon": "system",
                "noCache": True,
                "title": "系统管理"
            },
            "name": "系统管理",
            "path": "/system",
            "redirect": "noredirect"
        },
        {
            "alwaysShow": True,
            "children": [
                {
                    "component": "monitor/online/index",
                    "hidden": False,
                    "meta": {
                        "icon": "Steve-Jobs",
                        "noCache": True,
                        "title": "在线用户"
                    },
                    "name": "OnlineUser",
                    "path": "online"
                },
                {
                    "component": "monitor/log/index",
                    "hidden": False,
                    "meta": {
                        "icon": "log",
                        "noCache": False,
                        "title": "操作日志"
                    },
                    "name": "Log",
                    "path": "logs"
                },
                {
                    "component": "monitor/log/errorLog",
                    "hidden": False,
                    "meta": {
                        "icon": "error",
                        "noCache": True,
                        "title": "异常日志"
                    },
                    "name": "ErrorLog",
                    "path": "errorLog"
                },
                {
                    "component": "monitor/server/index",
                    "hidden": False,
                    "meta": {
                        "icon": "codeConsole",
                        "noCache": True,
                        "title": "服务监控"
                    },
                    "name": "ServerMonitor",
                    "path": "server"
                },
                {
                    "component": "monitor/sql/index",
                    "hidden": True,
                    "meta": {
                        "icon": "sqlMonitor",
                        "noCache": True,
                        "title": "SQL监控"
                    },
                    "name": "Sql",
                    "path": "druid"
                }
            ],
            "component": "Layout",
            "hidden": False,
            "meta": {
                "icon": "monitor",
                "noCache": True,
                "title": "系统监控"
            },
            "name": "系统监控",
            "path": "/monitor",
            "redirect": "noredirect"
        },
        {
            "alwaysShow": True,
            "children": [
                {
                    "component": "mnt/server/index",
                    "hidden": False,
                    "meta": {
                        "icon": "server",
                        "noCache": True,
                        "title": "服务器"
                    },
                    "name": "ServerDeploy",
                    "path": "mnt/serverDeploy"
                },
                {
                    "component": "mnt/app/index",
                    "hidden": False,
                    "meta": {
                        "icon": "app",
                        "noCache": True,
                        "title": "应用管理"
                    },
                    "name": "App",
                    "path": "mnt/app"
                },
                {
                    "component": "mnt/deploy/index",
                    "hidden": False,
                    "meta": {
                        "icon": "deploy",
                        "noCache": True,
                        "title": "部署管理"
                    },
                    "name": "Deploy",
                    "path": "mnt/deploy"
                },
                {
                    "component": "mnt/deployHistory/index",
                    "hidden": False,
                    "meta": {
                        "icon": "backup",
                        "noCache": True,
                        "title": "部署备份"
                    },
                    "name": "DeployHistory",
                    "path": "mnt/deployHistory"
                },
                {
                    "component": "mnt/database/index",
                    "hidden": False,
                    "meta": {
                        "icon": "database",
                        "noCache": True,
                        "title": "数据库管理"
                    },
                    "name": "Database",
                    "path": "mnt/database"
                }
            ],
            "component": "Layout",
            "hidden": False,
            "meta": {
                "icon": "mnt",
                "noCache": True,
                "title": "运维管理"
            },
            "name": "Mnt",
            "path": "/mnt",
            "redirect": "noredirect"
        },
        {
            "alwaysShow": True,
            "children": [
                {
                    "component": "generator/index",
                    "hidden": False,
                    "meta": {
                        "icon": "dev",
                        "noCache": False,
                        "title": "代码生成"
                    },
                    "name": "GeneratorIndex",
                    "path": "generator"
                },
                {
                    "component": "generator/config",
                    "hidden": True,
                    "meta": {
                        "icon": "dev",
                        "noCache": False,
                        "title": "生成配置"
                    },
                    "name": "GeneratorConfig",
                    "path": "generator/config/:tableName"
                },
                {
                    "component": "tools/storage/index",
                    "hidden": False,
                    "meta": {
                        "icon": "qiniu",
                        "noCache": True,
                        "title": "存储管理"
                    },
                    "name": "Storage",
                    "path": "storage"
                },
                {
                    "component": "tools/email/index",
                    "hidden": False,
                    "meta": {
                        "icon": "email",
                        "noCache": True,
                        "title": "邮件工具"
                    },
                    "name": "Email",
                    "path": "email"
                },
                {
                    "component": "tools/swagger/index",
                    "hidden": True,
                    "meta": {
                        "icon": "swagger",
                        "noCache": True,
                        "title": "接口文档"
                    },
                    "name": "Swagger",
                    "path": "swagger2"
                },
                {
                    "component": "tools/aliPay/index",
                    "hidden": False,
                    "meta": {
                        "icon": "alipay",
                        "noCache": True,
                        "title": "支付宝工具"
                    },
                    "name": "AliPay",
                    "path": "aliPay"
                },
                {
                    "component": "generator/preview",
                    "hidden": True,
                    "meta": {
                        "icon": "java",
                        "noCache": False,
                        "title": "生成预览"
                    },
                    "name": "Preview",
                    "path": "generator/preview/:tableName"
                }
            ],
            "component": "Layout",
            "hidden": False,
            "meta": {
                "icon": "sys-tools",
                "noCache": True,
                "title": "系统工具"
            },
            "name": "系统工具",
            "path": "/sys-tools",
            "redirect": "noredirect"
        },
        {
            "alwaysShow": True,
            "children": [
                {
                    "component": "components/Echarts",
                    "hidden": False,
                    "meta": {
                        "icon": "chart",
                        "noCache": False,
                        "title": "图表库"
                    },
                    "name": "Echarts",
                    "path": "echarts"
                },
                {
                    "component": "components/icons/index",
                    "hidden": False,
                    "meta": {
                        "icon": "icon",
                        "noCache": True,
                        "title": "图标库"
                    },
                    "name": "Icons",
                    "path": "icon"
                },
                {
                    "component": "components/Editor",
                    "hidden": False,
                    "meta": {
                        "icon": "fwb",
                        "noCache": True,
                        "title": "富文本"
                    },
                    "name": "Editor",
                    "path": "tinymce"
                },
                {
                    "component": "components/MarkDown",
                    "hidden": False,
                    "meta": {
                        "icon": "markdown",
                        "noCache": True,
                        "title": "Markdown"
                    },
                    "name": "Markdown",
                    "path": "markdown"
                },
                {
                    "component": "components/YamlEdit",
                    "hidden": False,
                    "meta": {
                        "icon": "dev",
                        "noCache": True,
                        "title": "Yaml编辑器"
                    },
                    "name": "YamlEdit",
                    "path": "yaml"
                }
            ],
            "component": "Layout",
            "hidden": False,
            "meta": {
                "icon": "zujian",
                "noCache": True,
                "title": "组件管理"
            },
            "name": "组件管理",
            "path": "/components",
            "redirect": "noredirect"
        },
        {
            "alwaysShow": True,
            "children": [
                {
                    "alwaysShow": True,
                    "children": [
                        {
                            "component": "nested/menu1/menu1-1",
                            "hidden": False,
                            "meta": {
                                "icon": "menu",
                                "noCache": False,
                                "title": "三级菜单1"
                            },
                            "name": "Test",
                            "path": "menu1-1"
                        },
                        {
                            "component": "nested/menu1/menu1-2",
                            "hidden": False,
                            "meta": {
                                "icon": "menu",
                                "noCache": True,
                                "title": "三级菜单2"
                            },
                            "name": "三级菜单2",
                            "path": "menu1-2"
                        }
                    ],
                    "component": "ParentView",
                    "hidden": False,
                    "meta": {
                        "icon": "menu",
                        "noCache": True,
                        "title": "二级菜单1"
                    },
                    "name": "二级菜单1",
                    "path": "menu1",
                    "redirect": "noredirect"
                },
                {
                    "component": "nested/menu2/index",
                    "hidden": False,
                    "meta": {
                        "icon": "menu",
                        "noCache": True,
                        "title": "二级菜单2"
                    },
                    "name": "二级菜单2",
                    "path": "menu2"
                }
            ],
            "component": "Layout",
            "hidden": False,
            "meta": {
                "icon": "menu",
                "noCache": True,
                "title": "多级菜单"
            },
            "name": "多级菜单",
            "path": "/nested",
            "redirect": "noredirect"
        }
    ]
    ```
    """
    return [
    {
        "alwaysShow": True,
        "children": [
            {
                "component": "system/user/index",
                "hidden": False,
                "meta": {
                    "icon": "peoples",
                    "noCache": True,
                    "title": "用户管理"
                },
                "name": "User",
                "path": "user"
            },
            {
                "component": "system/role/index",
                "hidden": False,
                "meta": {
                    "icon": "role",
                    "noCache": True,
                    "title": "角色管理"
                },
                "name": "Role",
                "path": "role"
            },
            {
                "component": "system/menu/index",
                "hidden": False,
                "meta": {
                    "icon": "menu",
                    "noCache": True,
                    "title": "菜单管理"
                },
                "name": "Menu",
                "path": "menu"
            },
            {
                "component": "system/dept/index",
                "hidden": False,
                "meta": {
                    "icon": "dept",
                    "noCache": True,
                    "title": "部门管理"
                },
                "name": "Dept",
                "path": "dept"
            },
            {
                "component": "system/job/index",
                "hidden": False,
                "meta": {
                    "icon": "Steve-Jobs",
                    "noCache": True,
                    "title": "岗位管理"
                },
                "name": "Job",
                "path": "job"
            },
            {
                "component": "system/dict/index",
                "hidden": False,
                "meta": {
                    "icon": "dictionary",
                    "noCache": True,
                    "title": "字典管理"
                },
                "name": "Dict",
                "path": "dict"
            },
            {
                "component": "system/timing/index",
                "hidden": False,
                "meta": {
                    "icon": "timing",
                    "noCache": True,
                    "title": "任务调度"
                },
                "name": "Timing",
                "path": "timing"
            }
        ],
        "component": "Layout",
        "hidden": False,
        "meta": {
            "icon": "system",
            "noCache": True,
            "title": "系统管理"
        },
        "name": "系统管理",
        "path": "/system",
        "redirect": "noredirect"
    },
    {
        "alwaysShow": True,
        "children": [
            {
                "component": "monitor/online/index",
                "hidden": False,
                "meta": {
                    "icon": "Steve-Jobs",
                    "noCache": True,
                    "title": "在线用户"
                },
                "name": "OnlineUser",
                "path": "online"
            },
            {
                "component": "monitor/log/index",
                "hidden": False,
                "meta": {
                    "icon": "log",
                    "noCache": False,
                    "title": "操作日志"
                },
                "name": "Log",
                "path": "logs"
            },
            {
                "component": "monitor/log/errorLog",
                "hidden": False,
                "meta": {
                    "icon": "error",
                    "noCache": True,
                    "title": "异常日志"
                },
                "name": "ErrorLog",
                "path": "errorLog"
            },
            {
                "component": "monitor/server/index",
                "hidden": False,
                "meta": {
                    "icon": "codeConsole",
                    "noCache": True,
                    "title": "服务监控"
                },
                "name": "ServerMonitor",
                "path": "server"
            },
            {
                "component": "monitor/sql/index",
                "hidden": True,
                "meta": {
                    "icon": "sqlMonitor",
                    "noCache": True,
                    "title": "SQL监控"
                },
                "name": "Sql",
                "path": "druid"
            }
        ],
        "component": "Layout",
        "hidden": False,
        "meta": {
            "icon": "monitor",
            "noCache": True,
            "title": "系统监控"
        },
        "name": "系统监控",
        "path": "/monitor",
        "redirect": "noredirect"
    },
    {
        "alwaysShow": True,
        "children": [
            {
                "component": "mnt/server/index",
                "hidden": False,
                "meta": {
                    "icon": "server",
                    "noCache": True,
                    "title": "服务器"
                },
                "name": "ServerDeploy",
                "path": "mnt/serverDeploy"
            },
            {
                "component": "mnt/app/index",
                "hidden": False,
                "meta": {
                    "icon": "app",
                    "noCache": True,
                    "title": "应用管理"
                },
                "name": "App",
                "path": "mnt/app"
            },
            {
                "component": "mnt/deploy/index",
                "hidden": False,
                "meta": {
                    "icon": "deploy",
                    "noCache": True,
                    "title": "部署管理"
                },
                "name": "Deploy",
                "path": "mnt/deploy"
            },
            {
                "component": "mnt/deployHistory/index",
                "hidden": False,
                "meta": {
                    "icon": "backup",
                    "noCache": True,
                    "title": "部署备份"
                },
                "name": "DeployHistory",
                "path": "mnt/deployHistory"
            },
            {
                "component": "mnt/database/index",
                "hidden": False,
                "meta": {
                    "icon": "database",
                    "noCache": True,
                    "title": "数据库管理"
                },
                "name": "Database",
                "path": "mnt/database"
            }
        ],
        "component": "Layout",
        "hidden": False,
        "meta": {
            "icon": "mnt",
            "noCache": True,
            "title": "运维管理"
        },
        "name": "Mnt",
        "path": "/mnt",
        "redirect": "noredirect"
    },
    {
        "alwaysShow": True,
        "children": [
            {
                "component": "generator/index",
                "hidden": False,
                "meta": {
                    "icon": "dev",
                    "noCache": False,
                    "title": "代码生成"
                },
                "name": "GeneratorIndex",
                "path": "generator"
            },
            {
                "component": "generator/config",
                "hidden": True,
                "meta": {
                    "icon": "dev",
                    "noCache": False,
                    "title": "生成配置"
                },
                "name": "GeneratorConfig",
                "path": "generator/config/:tableName"
            },
            {
                "component": "tools/storage/index",
                "hidden": False,
                "meta": {
                    "icon": "qiniu",
                    "noCache": True,
                    "title": "存储管理"
                },
                "name": "Storage",
                "path": "storage"
            },
            {
                "component": "tools/email/index",
                "hidden": False,
                "meta": {
                    "icon": "email",
                    "noCache": True,
                    "title": "邮件工具"
                },
                "name": "Email",
                "path": "email"
            },
            {
                "component": "tools/swagger/index",
                "hidden": True,
                "meta": {
                    "icon": "swagger",
                    "noCache": True,
                    "title": "接口文档"
                },
                "name": "Swagger",
                "path": "swagger2"
            },
            {
                "component": "tools/aliPay/index",
                "hidden": False,
                "meta": {
                    "icon": "alipay",
                    "noCache": True,
                    "title": "支付宝工具"
                },
                "name": "AliPay",
                "path": "aliPay"
            },
            {
                "component": "generator/preview",
                "hidden": True,
                "meta": {
                    "icon": "java",
                    "noCache": False,
                    "title": "生成预览"
                },
                "name": "Preview",
                "path": "generator/preview/:tableName"
            }
        ],
        "component": "Layout",
        "hidden": False,
        "meta": {
            "icon": "sys-tools",
            "noCache": True,
            "title": "系统工具"
        },
        "name": "系统工具",
        "path": "/sys-tools",
        "redirect": "noredirect"
    },
    {
        "alwaysShow": True,
        "children": [
            {
                "component": "components/Echarts",
                "hidden": False,
                "meta": {
                    "icon": "chart",
                    "noCache": False,
                    "title": "图表库"
                },
                "name": "Echarts",
                "path": "echarts"
            },
            {
                "component": "components/icons/index",
                "hidden": False,
                "meta": {
                    "icon": "icon",
                    "noCache": True,
                    "title": "图标库"
                },
                "name": "Icons",
                "path": "icon"
            },
            {
                "component": "components/Editor",
                "hidden": False,
                "meta": {
                    "icon": "fwb",
                    "noCache": True,
                    "title": "富文本"
                },
                "name": "Editor",
                "path": "tinymce"
            },
            {
                "component": "components/MarkDown",
                "hidden": False,
                "meta": {
                    "icon": "markdown",
                    "noCache": True,
                    "title": "Markdown"
                },
                "name": "Markdown",
                "path": "markdown"
            },
            {
                "component": "components/YamlEdit",
                "hidden": False,
                "meta": {
                    "icon": "dev",
                    "noCache": True,
                    "title": "Yaml编辑器"
                },
                "name": "YamlEdit",
                "path": "yaml"
            }
        ],
        "component": "Layout",
        "hidden": False,
        "meta": {
            "icon": "zujian",
            "noCache": True,
            "title": "组件管理"
        },
        "name": "组件管理",
        "path": "/components",
        "redirect": "noredirect"
    },
    {
        "alwaysShow": True,
        "children": [
            {
                "alwaysShow": True,
                "children": [
                    {
                        "component": "nested/menu1/menu1-1",
                        "hidden": False,
                        "meta": {
                            "icon": "menu",
                            "noCache": False,
                            "title": "三级菜单1"
                        },
                        "name": "Test",
                        "path": "menu1-1"
                    },
                    {
                        "component": "nested/menu1/menu1-2",
                        "hidden": False,
                        "meta": {
                            "icon": "menu",
                            "noCache": True,
                            "title": "三级菜单2"
                        },
                        "name": "三级菜单2",
                        "path": "menu1-2"
                    }
                ],
                "component": "ParentView",
                "hidden": False,
                "meta": {
                    "icon": "menu",
                    "noCache": True,
                    "title": "二级菜单1"
                },
                "name": "二级菜单1",
                "path": "menu1",
                "redirect": "noredirect"
            },
            {
                "component": "nested/menu2/index",
                "hidden": False,
                "meta": {
                    "icon": "menu",
                    "noCache": True,
                    "title": "二级菜单2"
                },
                "name": "二级菜单2",
                "path": "menu2"
            }
        ],
        "component": "Layout",
        "hidden": False,
        "meta": {
            "icon": "menu",
            "noCache": True,
            "title": "多级菜单"
        },
        "name": "多级菜单",
        "path": "/nested",
        "redirect": "noredirect"
    }
]


# 需要在定义api后,进行调用才会加入到app中
api_router.include_router(user_router)
api_router.include_router(table_router)
api_router.include_router(menus_router)
app.include_router(api_router)
app.include_router(auth_router)

if __name__ == '__main__':
    # create_table()

    uvicorn.run(
        settings.API_NAME,   # 需要使用字符串模块名才能reload
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=settings.LOG_LEVEL,
        reload=settings.API_RELOAD,
    )

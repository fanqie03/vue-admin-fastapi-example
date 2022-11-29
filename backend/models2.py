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
    


    def hash_password(self, password):
        self.password = custom_app_context.hash(password)

    # 密码解析
    def verify_password(self, password):
        return custom_app_context.verify(password, self.password)

    def create_access_token(self, data: dict = {}, EXPIRE_MINITE: Union[timedelta, None] = settings.EXPIRE_MINITE):
        to_encode = data.copy()
        expire = time.time() + EXPIRE_MINITE * 60
        to_encode.update({"exp": expire, "sub": str(self.user_id)}
                         )  # 加入用户名和超时时间  sub必须是字符串
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.SECRET_ALGORITHM)
        return encoded_jwt

    @classmethod
    def get_user(cls, session: Session = Depends(get_session), x_token: str = Header()):
        """HTTP headers 是大小写不敏感的"""
        user_id = cls.get_user_id(x_token)
        return session.get(cls, user_id)

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
    def login(cls, *, session: Session, username, password) -> Union['User', None]:
        user = session.exec(select(cls).where(cls.username == username)).first()
        if user == None:  # 没有该用户
            return
        if user.verify_password(password):  # 密码验证成功
            return user
        return  # 密码验证失败

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



# class LoginRead(User):
#     roles: List[Role]


# class User(Base):
#     __tablename__ = 'sys_user'
#     user_id = Column(Integer, primary_key=True, comment='用户id')
#     dept_id = Column(Integer, comment="部门id")
#     username = Column(String(255), index=True, comment='用户名')
#     nick_name = Column(String(255), comment='昵称')
#     gender = Column(String(2), comment='性别')
#     phone = Column(String(255), comment='手机号码')
#     email = Column(String(255), comment='邮箱')
#     avatar_name = Column(String(255), comment='头像地址')
#     avatar_path = Column(String(255), comment='头像真实路径')
#     password = Column(String(255), comment='密码')
#     is_admin = Column(Boolean, default=False, comment='是否是admin账号')
#     enabled = Column(Integer, comment='状态：1启动、0禁用')

#     create_by = Column(String(255), comment='创建者')
#     update_by = Column(String(255), comment='更新者')
#     pwd_reset_time = Column(String(255), comment='修改密码时间')
#     create_time = Column(DateTime, default=datetime.now, comment='创建日期')
#     update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新日期')

#     role = relationship('Role', secondary="sys_users_roles", backref=backref('users'), lazy='dynamic')
    

#     # 密码加密
#     def hash_password(self, password):
#         self.password = custom_app_context.hash(password)

#     # 密码解析
#     def verify_password(self, password):
#         return custom_app_context.verify(password, self.password)

#     def create_access_token(self, data: dict = {}, EXPIRE_MINITE: Union[timedelta, None] = settings.EXPIRE_MINITE):
#         to_encode = data.copy()
#         expire = time.time() + EXPIRE_MINITE * 60
#         to_encode.update({"exp": expire, "sub": str(self.user_id)}
#                          )  # 加入用户名和超时时间  sub必须是字符串
#         encoded_jwt = jwt.encode(
#             to_encode, settings.SECRET_KEY, algorithm=settings.SECRET_ALGORITHM)
#         return encoded_jwt

#     @classmethod
#     def get_user(cls, x_token: str = Header()):
#         """HTTP headers 是大小写不敏感的"""
#         user_id = cls.get_user_id(x_token)
#         return db.query(cls).filter(cls.id == user_id).first()

#     @classmethod
#     def get_user_id(cls, x_token: str = Header()):
#         credentials_exception = HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Could not validate credentials"
#         )
#         try:
#             payload = jwt.decode(x_token, settings.SECRET_KEY,
#                                  algorithms=settings.SECRET_ALGORITHM)
#             user_id: str = payload.get("sub")
#             if user_id is None:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="找不到user_id"
#                 )
#             if payload.get('exp') - time.time() <= 0:  # 超时
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,  # 重新登陆
#                     detail="超时,请重新登陆"
#                 )
#         except ExpiredSignatureError as e:
#             logger.exception('jwt解析的时候如果令牌超会自动抛出异常,使用exp关键字')
#             raise e
#         except JWTError:
#             logger.exception("解析失败")
#             raise credentials_exception
#         return user_id

#     @classmethod
#     def login(cls, username, password) -> Union['User', None]:
#         user = db.query(cls).filter(cls.username == username).first()
#         if user == None:  # 没有该用户
#             return
#         if user.verify_password(password):  # 密码验证成功
#             return user
#         return  # 密码验证失败


# class Role(Base):
#     __tablename__ = 'sys_role'
#     role_id = Column(Integer, primary_key=True, comment='ID')
#     name = Column(String(255), comment="名称")
#     level = Column(Integer, index=True, comment='角色级别')
#     description = Column(String(255), comment='描述')
#     data_scope = Column(String(2), comment='数据权限')

#     create_by = Column(String(255), comment='创建者')
#     update_by = Column(String(255), comment='更新者')
#     create_time = Column(DateTime, default=datetime.now, comment='创建日期')
#     update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新日期')

#     menus = relationship('Menu', secondary="sys_roles_menus", backref=backref('roles'), lazy='dynamic')

# class UserRole(Base):
#     __tablename__ = 'sys_users_roles'
#     user_id = Column(Integer, ForeignKey('sys_user.user_id'), primary_key=True,  comment='用户ID')
#     role_id = Column(Integer, ForeignKey('sys_role.role_id'), primary_key=True,  comment='角色ID')


# class Menu(Base):
#     __tablename__ = 'sys_menu'
#     menu_id = Column(Integer, primary_key=True, comment='ID')
#     pid = Column(Integer, comment="上级菜单ID")
#     sub_count = Column(Integer, comment="子菜单数目")
#     type = Column(Integer, comment="菜单类型")
#     title = Column(String(255), comment="菜单标题")
#     name = Column(String(255), comment="组件名称")
#     component = Column(Integer, index=True, comment='组件')
#     munu_sort = Column(Integer, comment='排序')
#     icon = Column(String(255), comment='图标')
#     path = Column(String(255), comment='链接地址')
#     i_frame = Column(Boolean, comment='是否外链')
#     cache = Column(Boolean, comment='缓存')
#     hidden = Column(Boolean, comment='隐藏')
#     permission = Column(String(255), comment='权限')

#     create_by = Column(String(255), comment='创建者')
#     update_by = Column(String(255), comment='更新者')
#     create_time = Column(DateTime, default=datetime.now, comment='创建日期')
#     update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新日期')


# class RoleMenu(Base):
#     __tablename__ = 'sys_roles_menus'
#     menu_id = Column(Integer, ForeignKey('sys_menu.menu_id'), primary_key=True, comment='菜单ID')
#     role_id = Column(Integer, ForeignKey('sys_role.role_id'), primary_key=True, comment='角色ID')


# class Article(Base):
#     __tablename__ = 'article'
#     id = Column(Integer, primary_key=True)
#     title = Column(String(128), comment='标题|内容')
#     status = Column(String(32), comment='状态')
#     author = Column(String(32), comment='作者')
#     display_time = Column(DateTime(), comment='创建时间')
#     pageviews = Column(String(128), comment='浏览次数')

# def create_table():
#     logger.info("重置数据库 ...")
#     Base.metadata.drop_all(bind=engine)
#     Base.metadata.create_all(bind=engine)

#     users = [('admin', '123456'), ('guest', '123456')]
#     logger.info(f"创建账号 {users} ...")
#     for username, password in users:
#         user = User(username=username)
#         user.hash_password(password)
#         db.add(user)
#     db.commit()
#     logger.info(f"创建随机文章 {10} ...")
#     items = []
#     for i in range(10):
#         items.append({
#         'id': fake.unique.random_int(min=1, max=999),  # 随机且唯一
#         'title': fake.text(),
#         'status': random.choice(['published', 'draft', 'deleted']),
#         'author': fake.name(),
#         'display_time': fake.date_time(),
#         'pageviews': fake.random_int(min=300, max=5000)
#     })
#     articles = [Article(**x) for x in items]
#     db.add_all(articles)
#     db.commit()
    

"""
========
数据操作
========
"""
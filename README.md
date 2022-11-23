# vue-admin-fastapi-example

[简体中文](./README.md) | [English](./README-en.md)

## 简介

[vue-admin-template](https://github.com/PanJiaChen/vue-admin-template)和[FastAPI](https://github.com/tiangolo/fastapi)前后端分离的小例子

- 项目小，python端只有一个文件
- 用户登陆，JWT令牌认证
- 密码哈希
- 前后端分离
- CORS跨域访问
- 使用FastAPI
- 使用SQLAlchemy ORM框架
- 包含docker

## 项目结构

```sh
vue-admin-fastapi-example
├── backend  # 后台项目
│   ├── admin  # 前端构建过后的文件
│   ├── log  # 后台日志文件
│   ├── manage.py  # python主要文件
│   └── requirements.txt  # python依赖文件
├── docker  # docker配置文件
│   ├── docker-compose.yaml
│   └── Dockerfile
├── docs  # 文档说明
├── frontend  # 前端项目
├── README-en.md
└── README.md
```

## 运行项目

克隆本项目，进入后

打开backend文件
```sh
cd backend
```

安装依赖
```sh
pip install requirements.txt
```

运行文件
```sh
python manage.py
```

## 重新构建

### 手动构建

> nodejs 14 可以

在frontend目录下运行

```sh
npm install
npm run build:prod
```

将dist目录下的文件复制到 `/backend/admin/` 目录下,在backend目录下运行

```sh
python manage.py
```

### 使用docker

构建image

```sh
docker build -t vue-admin-fastapi-examples:0.1 -f docker/Dockerfile  .
```

运行image

```sh
docker run -it --rm -p 8000:8000 vue-admin-fastapi-examples:0.1
```

### 使用docker-compose

```sh
docker-compose -f docker/docker-compose.yaml up -d
```

## 项目预览

|  |
|---------------------|
| ![](docs/img/1.png) | 
| ![](docs/img/2.png) | 


## 参考项目

- [FastAPI](https://github.com/tiangolo/fastapi)
- [vue-admin-flask-example](https://github.com/bay1/vue-admin-flask-example)
- [vue-admin-template](https://github.com/PanJiaChen/vue-admin-template)
FROM nikolaik/python-nodejs:python3.7-nodejs14

ENV TIME_ZONE Asia/Shanghai
ENV API_RELOAD 0
ENV PIPURL "https://pypi.tuna.tsinghua.edu.cn/simple"

RUN echo "${TIME_ZONE}" > /etc/timezone && ln -sf /usr/share/zoneinfo/${TIME_ZONE} /etc/localtime

EXPOSE 8000

COPY . /app
WORKDIR /app/frontend

# build nodejs
RUN npm install --registry=https://registry.npm.taobao.org \
    && npm run build:prod && rm -rf node_modules \
    && cp -r dist/* ../backend/admin 

# # prepare python
WORKDIR /app/backend
RUN pip --no-cache-dir install -r requirements.txt -i ${PIPURL} 

CMD python manage.py
# CMD /bin/bash

# --progress=plain
# docker build -t vue-admin-fastapi-examples:0.1 -f docker/Dockerfile  .
# docker run -it --rm -p 8000:8000 vue-admin-fastapi-examples:0.1

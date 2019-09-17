FROM python:3.5-alpine3.9
MAINTAINER Douglas Coburn

COPY requirements.txt /app/requirements.txt
COPY ssl/server.crt /app/ssl/server.crt
COPY ssl/server.key /app/ssl/server.key

RUN apk update && apk add curl &&  rm -rf /var/cache/apk/* 
RUN pip3 install -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python3", "scim_server_sigsci.py"]
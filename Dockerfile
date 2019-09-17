FROM python:3.5-alpine3.9
MAINTAINER Douglas Coburn

COPY requirements.txt /app/requirements.txt
COPY ssl /app/ssl
COPY templates /app/templates
COPY scim_server_sigsci.py /app/scim_server_sigsci.py

RUN apk update && apk add curl &&  rm -rf /var/cache/apk/* 
RUN pip3 install -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python3", "/app/scim_server_sigsci.py"]
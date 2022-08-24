FROM python:3.8-slim-buster

WORKDIR /app
ENV HOME /tmp

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY main.py main.py

CMD [ "python3", "main.py" , "-r", "all"]

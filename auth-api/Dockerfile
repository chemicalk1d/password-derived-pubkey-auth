FROM python:3.8-slim

EXPOSE 5000

CMD ["python", "main.py"]

RUN mkdir /app

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install -r requirements.txt

COPY . .


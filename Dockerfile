FROM python:3.10

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY jws2pubkey.py ./
ENTRYPOINT ["python", "jws2pubkey.py"]

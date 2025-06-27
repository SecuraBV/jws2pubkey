FROM python:3.10

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY jws_get_rsa_pubkey.py ./
ENTRYPOINT ["python", "jws_get_rsa_pubkey.py"]

FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /flask-cqlalchemy
RUN	git clone https://github.com/rangerthegood/flask-cqlalchemy.git ; \
	cd flask-cqlalchemy; \
	python setup.py install

WORKDIR /usr/src/app

COPY . .

CMD [ "flask", "run", "--host=0.0.0.0" ]

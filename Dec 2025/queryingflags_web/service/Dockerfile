FROM python:3.10-slim

WORKDIR /app

COPY app.py .
COPY flags.py .
COPY index.html .

RUN pip install Flask

ENV FLASK_APP=app.py

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]

FROM python:alpine
RUN apk add --no-cache git
RUN mkdir /app
WORKDIR /app
COPY . .
ENV FLASK_APP "src/app:create_app()"
ENV FLASK_ENV local
ENV FLASK_DEBUG 1
RUN pip install -r requirements.txt
EXPOSE 5566
CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0", "--port=5566"]

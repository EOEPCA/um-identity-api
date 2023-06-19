FROM python:alpine
RUN mkdir /app
WORKDIR /app
COPY conf src requirements.txt ./
RUN pip install -r requirements.txt
EXPOSE 5566
CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]

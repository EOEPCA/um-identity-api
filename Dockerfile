FROM python:alpine
RUN mkdir /app
WORKDIR /app
COPY identity-api/conf identity-api/src identity-api/requirements.txt ./
COPY utils/ ./src/utils/
RUN pip install -r requirements.txt
EXPOSE 5566
CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]

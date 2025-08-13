FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir tornado==6.4.1
COPY app /app/app
EXPOSE 8080
CMD ["python", "-m", "app.main"]

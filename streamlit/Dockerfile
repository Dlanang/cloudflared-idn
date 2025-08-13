FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir streamlit==1.37.1 pandas==2.2.2 watchdog==4.0.2
COPY app /app/app
EXPOSE 8501

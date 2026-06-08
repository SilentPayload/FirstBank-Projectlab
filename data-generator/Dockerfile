FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY generate_logs.py .

ENV OUTPUT_DIR=/output
ENV STUDENT_SEED=12345

CMD ["python", "generate_logs.py"]

# Use an official Python runtime as a parent image
FROM ubuntu:24.04

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-venv python3-dev python3-pip \
    build-essential tzdata pkg-config \
    cron


# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
RUN mkdir -p /app/api_classes
COPY api_classes/mail_api.py /app/api_classes/mail_api.py
COPY requirements.txt .
COPY main.py .
RUN python3 -mvenv /app/env
RUN /app/env/bin/pip install --upgrade pip wheel setuptools && \ 
/app/env/bin/pip install -r requirements.txt

# Copy the application files
COPY . /app/

# Set timezone to EST
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime && dpkg-reconfigure -f noninteractive tzdata

# Add cron job
RUN echo "0 8 * * * root /app/cron_run.sh > /var/log/cron.log 2>&1" > /etc/cron.d/cvealerts

# Set permissions and apply cron job
RUN chmod 0644 /etc/cron.d/cvealerts && crontab /etc/cron.d/cvealerts

# Copy the entrypoint script and ensure it's executable
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set the entrypoint script
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]

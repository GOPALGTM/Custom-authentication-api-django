# Use the official Python image as the base image
FROM python:3.10.6

# Set work directory
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . /app/

# Expose the port your Django app runs on
EXPOSE 8000
CMD [ "python3","manage.py","runserver","0.0.0.0:8000" ]
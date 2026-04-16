# base image — lightweight python on alpine linux
# alpine = minimal linux, weighs ~5mb instead of ~900mb
FROM python:3.12-alpine

# working directory inside the container
# all commands below will run from here
WORKDIR /app

# copy dependencies file first
# docker caches layers if requirements.txt hasn't changed,
# pip install won't run again on rebuild
COPY requirements.txt .

# install dependencies
# --no-cache-dir = don't save pip cache (saves space in image)
RUN pip install --no-cache-dir -r requirements.txt

# copy all project code into the container
COPY generator.py .
COPY threat_intel.py .

# default environment variables
# can be overridden in docker-compose.yml
ENV ATTACK=all
ENV INTERVAL=0.5

# command that runs when the container starts
CMD ["python3", "generator.py"]
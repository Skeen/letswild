FROM python:3-slim
# TODO: Handle docker-in-docker - Potentially by spawning sieblings

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

# NOTE: Production build for smaller images
# Copy the requirements files and install packages
#COPY requirements.txt /usr/src/app/requirements.txt
# Install dependencies
#RUN apt-get update && \
#    apt-get install -y git build-essential gettext && \
#    pip install --no-cache-dir -r requirements.txt && \
#    apt-get remove -y --purge git build-essential binutils gcc-6 && \
#    apt-get autoremove -y && \
#    apt-get clean && \
#    rm -rf /var/lib/apt/lists/*

# NOTE: Test build for quicker changes
# Install dependencies
RUN apt-get update
RUN apt-get install -y git build-essential gettext
# Copy the requirements files and install packages
COPY requirements.txt /usr/src/app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire source in
COPY . /usr/src/app/

# Copy startpoint in
COPY docker/start.sh /usr/src/app
EXPOSE 8000
CMD ["./start.sh"]

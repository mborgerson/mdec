FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy unzip python3 python3-pip libdbus-1-3

WORKDIR /opt
COPY private/BinaryNinja-dev.zip .
RUN unzip BinaryNinja-dev.zip
RUN rm BinaryNinja-dev.zip
WORKDIR /opt/binaryninja
COPY private/license.txt .
RUN ./scripts/install_api.py

COPY mdec-binja /mdec-binja
RUN pip install /mdec-binja
RUN rm -rf /mdec-binja

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

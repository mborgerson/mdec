FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy unzip python3 python3-pip

RUN pip install aiohttp angr

COPY mdec-angr /mdec-angr
RUN pip install /mdec-angr
RUN rm -rf /mdec-angr

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

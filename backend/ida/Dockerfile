FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy python3 python3-pip

WORKDIR /opt/ida
COPY private/ida_latest.tar.bz2 .
RUN tar xf ida_latest.tar.bz2 && rm ida_latest.tar.bz2
RUN /opt/ida/install_dependencies_64bit.sh
COPY decompile_all.py .

WORKDIR /root
COPY private/license_stuff.tgz .
RUN tar xvf license_stuff.tgz

COPY mdec-ida /mdec-ida
RUN pip install /mdec-ida
RUN rm -rf /mdec-ida

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

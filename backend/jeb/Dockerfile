FROM ubuntu:20.04 as base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy python3 python3-pip


FROM base as jeb
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -qy unzip default-jdk wget

ENV JEB_URL https://www.pnfsoftware.com/dl?jeb4ce
WORKDIR /opt/jeb
RUN wget -O jeb.zip -nv ${JEB_URL}
RUN unzip jeb.zip && rm jeb.zip

COPY DecompileFile.py /opt/jeb
COPY private/jeb-client.cfg /opt/jeb/bin/jeb-client.cfg

COPY common/mdec-base /mdec-base
COPY jeb/mdec-jeb /mdec-jeb
RUN pip install /mdec-base /mdec-jeb \
 && rm -rf /mdec-base /mdec-jeb

#
# Base
#
FROM ubuntu:20.04 as base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy python3 python3-pip
COPY common/mdec-base /mdec-base
RUN pip install /mdec-base \
 && rm -rf /mdec-base

#
# angr
#
FROM base as angr

COPY angr/mdec-angr /mdec-angr
RUN pip install /mdec-angr
RUN rm -rf /mdec-angr

CMD ["python3", "-m", "mdecangr"]

#
# Binary Ninja
#
FROM base as binja
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -qy unzip libdbus-1-3

WORKDIR /opt
COPY binja/private/BinaryNinja-dev.zip .
RUN unzip BinaryNinja-dev.zip
RUN rm BinaryNinja-dev.zip
WORKDIR /opt/binaryninja
COPY binja/private/license.txt .
RUN ./scripts/install_api.py

COPY binja/mdec-binja /mdec-binja
RUN pip install /mdec-binja \
 && rm -rf /mdec-binja

CMD ["python3", "-m", "mdecbinja"]

#
# Ghidra
#
FROM base as ghidra
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -qy unzip default-jdk wget

ENV GHIDRA_URL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip
ENV GHIDRA_SHA256 ac96fbdde7f754e0eb9ed51db020e77208cdb12cf58c08657a2ab87cb2694940
WORKDIR /opt/ghidra
RUN wget -nv ${GHIDRA_URL}
RUN echo "${GHIDRA_SHA256}  $(basename ${GHIDRA_URL})" | sha256sum -c - \
 && unzip $(basename ${GHIDRA_URL}) \
 && rm $(basename ${GHIDRA_URL}) \
 && mv /opt/ghidra/* /tmp/ghidra \
 && mv /tmp/ghidra/* /opt/ghidra

COPY ghidra/mdec-ghidra /mdec-ghidra
RUN pip install /mdec-ghidra \
 && rm -rf /mdec-ghidra

COPY ghidra/dump.py /opt/ghidra/dump.py

CMD ["python3", "-m", "mdecghidra"]

#
# IDA
#
FROM base as ida
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /opt/ida
COPY ida/private/ida_latest.tar.bz2 .
RUN tar xf ida_latest.tar.bz2 && rm ida_latest.tar.bz2
RUN /opt/ida/install_dependencies_64bit.sh
COPY ida/decompile_all.py .

WORKDIR /root
COPY ida/private/license_stuff.tgz .
RUN tar xf license_stuff.tgz

COPY ida/mdec-ida /mdec-ida
RUN pip install /mdec-ida \
 && rm -rf /mdec-ida

CMD ["python3", "-m", "mdecida"]

FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy unzip python3 python3-pip default-jdk wget


ENV GHIDRA_URL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip
ENV GHIDRA_SHA256 ac96fbdde7f754e0eb9ed51db020e77208cdb12cf58c08657a2ab87cb2694940
WORKDIR /opt/ghidra
RUN wget ${GHIDRA_URL}
RUN echo "${GHIDRA_SHA256}  $(basename ${GHIDRA_URL})" | sha256sum -c - \
 && unzip $(basename ${GHIDRA_URL}) \
 && rm $(basename ${GHIDRA_URL}) \
 && mv /opt/ghidra/* /tmp/ghidra \
 && mv /tmp/ghidra/* /opt/ghidra

COPY mdec-ghidra /mdec-ghidra
RUN pip install /mdec-ghidra
RUN rm -rf /mdec-ghidra

COPY dump.py /opt/ghidra/dump.py

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

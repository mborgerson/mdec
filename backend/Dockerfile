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

#
# Reko
#
FROM base as reko
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -qy wget apt-transport-https build-essential gcc g++ cmake libcapstone-dev pkg-config p7zip-full git unzip

RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
RUN dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
RUN apt-get update
RUN apt-get install -qy dotnet-sdk-5.0

RUN git clone --depth=1 https://github.com/uxmal/reko
RUN cd reko \
 && dotnet msbuild -p:Platform=x64 -p:Configuration=UnixRelease -t:build_solution -m ./src/BuildTargets/BuildTargets.csproj \
 && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_runtime_nupkg -m ./src/BuildTargets/BuildTargets.csproj \
 && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_release -m ./src/BuildTargets/BuildTargets.csproj
WORKDIR /opt/reko
RUN unzip /reko/src/../bin/CmdLine-0.11.0-5a37a1ed21.zip \
 && rm -rf /reko

COPY reko/mdec-reko /mdec-reko
RUN pip install /mdec-reko \
 && rm -rf /mdec-reko

CMD ["python3", "-m", "mdecreko"]

#
# RetDec
#

FROM base as retdec
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/
RUN apt-get install -qy wget
ENV RETDEC_URL=https://retdec-tc.avast.com/repository/download/RetDec_LinuxBuild/.lastSuccessful/package/retdec-master-linux-64b.tar.xz?guest=1
RUN wget -nv ${RETDEC_URL}
RUN tar xvf $(basename ${RETDEC_URL}) \
 && rm $(basename ${RETDEC_URL})

COPY retdec/mdec-retdec /mdec-retdec
RUN pip install /mdec-retdec \
 && rm -rf /mdec-retdec

CMD ["python3", "-m", "mdecretdec"]

#
# Snowman
#
FROM base as snowman
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy  build-essential cmake libboost-dev qt5-default git

RUN cd /tmp \
 && git clone --depth=1 https://github.com/yegord/snowman.git \
 && mkdir -p snowman/build \
 && cd snowman/build \
 && cmake -DCMAKE_INSTALL_PREFIX=/opt/snowman ../src \
 && make -j$(nproc) install \
 && cd / && rm -rf /tmp/snowman

COPY snowman/mdec-snowman /mdec-snowman
RUN pip install /mdec-snowman \
 && rm -rf /mdec-snowman

CMD ["python3", "-m", "mdecsnowman"]

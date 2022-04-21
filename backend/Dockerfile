#
# Base
#
FROM ubuntu:20.04 as base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy python3 python3-pip

RUN useradd -m --uid 1000 mdec && echo mdec:d094308474f96d721996e87717e6b3be | chpasswd

#
# angr
#
FROM base as angr

COPY common/mdec-base /mdec-base
COPY angr/mdec-angr /mdec-angr
RUN pip install /mdec-base /mdec-angr \
 && rm -rf /mdec-base /mdec-angr

USER mdec
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
RUN ./scripts/install_api.py root

COPY common/mdec-base /mdec-base
COPY binja/mdec-binja /mdec-binja
RUN pip install /mdec-base /mdec-binja \
 && rm -rf /mdec-base /mdec-binja

USER mdec
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
COPY ghidra/dump.py /opt/ghidra/dump.py
COPY ghidra/version.py /opt/ghidra/version.py

COPY common/mdec-base /mdec-base
COPY ghidra/mdec-ghidra /mdec-ghidra
RUN pip install /mdec-base /mdec-ghidra \
 && rm -rf /mdec-base /mdec-ghidra

USER mdec
CMD ["python3", "-m", "mdecghidra"]

#
# Hex-Rays Decompiler
#
FROM base as hexrays

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /opt/hexrays
COPY hexrays/private/ida_latest.tar.bz2 .
RUN tar xf ida_latest.tar.bz2 && rm ida_latest.tar.bz2
RUN /opt/hexrays/install_dependencies_64bit.sh
COPY hexrays/decompile_all.py .
COPY hexrays/version.py .

COPY common/mdec-base /mdec-base
COPY hexrays/mdec-hexrays /mdec-hexrays
RUN pip install /mdec-base /mdec-hexrays \
 && rm -rf /mdec-base /mdec-hexrays

USER mdec
WORKDIR /home/mdec
COPY hexrays/private/license_stuff.tgz .
RUN tar xf license_stuff.tgz
CMD ["python3", "-m", "mdechexrays"]

#
# r2dec
#
FROM base as r2dec

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -qy  build-essential cmake git
RUN ln -sf /usr/bin/python3 /usr/bin/python

USER mdec

RUN cd /home/mdec \
 && git clone --depth=1 https://github.com/radareorg/radare2 \
 && cd radare2 \
 && ./sys/user.sh \
 && export PATH=$PATH:/home/mdec/bin \
 && r2pm init \
 && r2pm -ci r2dec

USER root
COPY common/mdec-base /mdec-base
COPY r2dec/mdec-r2dec /mdec-r2dec
RUN pip install /mdec-base /mdec-r2dec \
 && rm -rf /mdec-base /mdec-r2dec

USER mdec
ENV PATH=$PATH:/home/mdec/bin
CMD ["python3", "-m", "mdecr2dec"]

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

RUN git clone --depth=1 https://github.com/uxmal/reko -b version-0.11.0
RUN cd reko \
 && dotnet msbuild -p:Platform=x64 -p:Configuration=UnixRelease -t:build_solution -m ./src/BuildTargets/BuildTargets.csproj \
 && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_runtime_nupkg -m ./src/BuildTargets/BuildTargets.csproj \
 && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_release -m ./src/BuildTargets/BuildTargets.csproj
WORKDIR /opt/reko
RUN unzip /reko/src/../bin/CmdLine-*.zip \
 && rm -rf /reko

COPY common/mdec-base /mdec-base
COPY reko/mdec-reko /mdec-reko
RUN pip install /mdec-base /mdec-reko \
 && rm -rf /mdec-base /mdec-reko

USER mdec
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

COPY common/mdec-base /mdec-base
COPY retdec/mdec-retdec /mdec-retdec
RUN pip install /mdec-base /mdec-retdec \
 && rm -rf /mdec-base /mdec-retdec

USER mdec
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

COPY common/mdec-base /mdec-base
COPY snowman/mdec-snowman /mdec-snowman
RUN pip install /mdec-base /mdec-snowman \
 && rm -rf /mdec-base /mdec-snowman

USER mdec
CMD ["python3", "-m", "mdecsnowman"]

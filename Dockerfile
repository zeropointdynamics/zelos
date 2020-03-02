FROM       ubuntu:bionic
MAINTAINER "Kevin Z. Snow <kevin@zeropointdynamics.com>"

RUN apt-get update && \
	apt-get -y upgrade && \
	apt-get install -y python3 python3-pip python3-venv git cmake

RUN useradd -s /bin/bash -m zelos
RUN su - zelos -c "python3 -m venv /home/zelos/.venv/zelos"
RUN su - zelos -c "source /home/zelos/.venv/zelos/bin/activate && git clone https://github.com/zeropointdynamics/zelos && cd zelos && pip install -e '.[dev]'"
RUN su - zelos -c "echo 'source /home/zelos/.venv/zelos/bin/activate' >> /home/zelos/.bashrc"
CMD su - zelos

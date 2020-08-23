FROM perl

# install required dependencies
RUN apt update && apt install -y libio-socket-ssl-perl \
	libdigest-hmac-perl \
	libterm-readkey-perl \
	libmime-lite-perl \
	libfile-libmagic-perl \
	libio-socket-inet6-perl \
        libnet-dns-perl

# throw script into docker
COPY smtp-cli /usr/bin/

# add user
RUN adduser --disabled-password --gecos "" noroot

# switch to user
USER noroot

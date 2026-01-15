# use the jail base image
FROM redpwn/jail
# copy the root files from any Docker image
COPY --from=debian:latest / /srv

ENV JAIL_PORT=5555

WORKDIR /srv/app/

# setup the binary to run
COPY ./flag.txt /srv/app/flag.txt
COPY ./hohoheap /srv/app/run
RUN chmod +x /srv/app/run

FROM golang
RUN apt-get update && apt-get install -y pass gnome-keyring dbus-x11 libsecret-tools
COPY docker/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD /bin/bash

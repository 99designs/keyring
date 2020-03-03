FROM golang:1.14-buster
RUN apt-get update && apt-get install -y pass gnome-keyring dbus-x11 libsecret-tools
CMD /bin/bash

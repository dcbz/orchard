#!/bin/bash
set -e

# Start D-Bus (required by Avahi)
mkdir -p /run/dbus
dbus-daemon --system --nofork &
sleep 1

# Start Avahi daemon in foreground with verbose logging
avahi-daemon --no-drop-root --debug &
sleep 2

# Register some services so there are records to attack
# The hostname is set by docker-compose
HOSTNAME=$(hostname)

echo "[victim] Hostname: ${HOSTNAME}.local"
echo "[victim] Avahi started. Publishing services..."

# Publish a fake printer service
avahi-publish-service "${HOSTNAME} Printer" _ipp._tcp 631 \
    "ty=HP LaserJet" "pdl=application/postscript" &

# Publish an SSH service
avahi-publish-service "${HOSTNAME} SSH" _ssh._tcp 22 &

# Publish an HTTP service
avahi-publish-service "${HOSTNAME} Web" _http._tcp 80 "path=/" &

echo "[victim] Services published. Waiting..."

# Keep container alive
wait

#!/usr/bin/env bash
# setup-snort-hids.sh
# Usage: sudo ./setup-snort-hids.sh
# Tujuan: install Snort (HIDS), Mosquitto, Python deps, snort2mqtt service, contoh rules.
# Tested target: Ubuntu 20.04 / 22.04 (best-effort).
# NOTE: Pastikan jalankan sebagai root / dengan sudo.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "=== START: Install prerequisites & repositories ==="

apt update
apt -y upgrade

# Basic build/util tools (some may be used by Snort packages or future compilation)
apt -y install build-essential cmake git bison flex libpcap-dev libpcap0.8 \
    libpcre3 libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev liblz4-tool \
    libssl-dev pkg-config python3 python3-pip python3-venv wget curl

echo "=== Install Snort (from apt) ==="
# Install snort non-interactively
# For some distributions this will prompt for network interface; we preseed with loopback as placeholder.
echo "snort snort/install_interfaces string any" | debconf-set-selections || true
apt -y install snort

echo "=== Configure /var/log/snort and permissions ==="
mkdir -p /var/log/snort
chown -R snort:snort /var/log/snort || true

SNORT_CONF="/etc/snort/snort.conf"
LOCAL_RULES="/etc/snort/rules/local.rules"
EVE_JSON="/var/log/snort/eve.json"

# Backup existing snort.conf
if [ -f "$SNORT_CONF" ]; then
  cp -n "$SNORT_CONF" "${SNORT_CONF}.bak-$(date +%s)" || true
fi

echo "=== Deploy minimal snort.conf adjustments (non-destructive) ==="

# Insert local.rules include and JSON output (if not present)
# We will attempt to enable JSON output (alert_json) if supported. Otherwise alerts will still go to /var/log/snort/alert.
# Use awk to check if include and output exist, and append otherwise.
if ! grep -q "include \$RULE_PATH/local.rules" "$SNORT_CONF"; then
  echo "" >> "$SNORT_CONF"
  echo "# Include local custom rules" >> "$SNORT_CONF"
  echo "include \$RULE_PATH/local.rules" >> "$SNORT_CONF"
fi

# Try to add JSON output directive
if ! grep -q "output alert_json" "$SNORT_CONF" ; then
  cat >> "$SNORT_CONF" <<'EOF'

# --- Added by PKL setup script: enable JSON alert output (eve-like) ---
# Note: Some Snort2 package builds support "output alert_json" plugin.
# If this directive fails on service start, remove it and fallback to unified2 + barnyard2 (see README notes).
output alert_json: file { /var/log/snort/eve.json }
# --- end added block ---
EOF
fi

# Ensure RULE_PATH defined in snort.conf - fallback create basic rules dir
if ! grep -q "^var RULE_PATH" "$SNORT_CONF"; then
  # Add defaults near top if missing
  sed -i '1s;^;var RULE_PATH /etc/snort/rules\nvar SO_RULE_PATH /etc/snort/so_rules\nvar PREPROC_RULE_PATH /etc/snort/preproc_rules\n;' "$SNORT_CONF"
fi

# Create rules directory and a minimal local.rules
mkdir -p /etc/snort/rules
cat > "$LOCAL_RULES" <<'RULES'
# local.rules - example rules for HIDS PKL
# Rule SID range 1000000+ for local rules

# Simple SSH attempt detection (adjust ports for your environment)
alert tcp any any -> any 22 (msg:"LOCAL SSH connection attempt"; sid:1000001; rev:1; classtype:attempted-admin; priority:2;)

# Simple NMAP SYN scan detection (example)
alert tcp any any -> any 80 (msg:"LOCAL HTTP access - generic (example)"; sid:1000002; rev:1;)
RULES

chown -R snort:snort /etc/snort || true

echo "=== Ensure log file for JSON exists and correct perms ==="
touch "$EVE_JSON" || true
chown snort:snort "$EVE_JSON" || true
chmod 640 "$EVE_JSON" || true

echo "=== Install Mosquitto (MQTT broker) ==="
apt -y install mosquitto mosquitto-clients
systemctl enable --now mosquitto

echo "=== Install Python deps and deploy snort2mqtt.py ==="
pip3 install --upgrade pip
pip3 install paho-mqtt

SNORT2MQTT_PATH="/usr/local/bin/snort2mqtt.py"
cat > "$SNORT2MQTT_PATH" <<'PY'
#!/usr/bin/env python3
"""
snort2mqtt.py
Simple tail reader for Snort JSON alerts -> publish to MQTT topic.
Place this file at /usr/local/bin/snort2mqtt.py and make executable.
"""
import time, json, os
import paho.mqtt.publish as publish

# CONFIG - edit if needed
EVE_FILE = "/var/log/snort/eve.json"
MQTT_BROKER = "127.0.0.1"
MQTT_TOPIC = "disdukcapil/snort/host-alerts"
MQTT_USER = None
MQTT_PASS = None

def follow(thefile):
    thefile.seek(0, os.SEEK_END)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def filter_event(obj):
    # Only forward actual alerts
    if obj.get('event_type') != 'alert':
        return False
    return True

def main():
    if not os.path.exists(EVE_FILE):
        print("EVE file not found:", EVE_FILE)
        return
    with open(EVE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in follow(f):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if not filter_event(obj):
                continue
            msg = {
                "sid": obj.get('alert', {}).get('signature_id'),
                "sig": obj.get('alert', {}).get('signature'),
                "src": obj.get('src_ip'),
                "dst": obj.get('dest_ip'),
                "proto": obj.get('proto'),
                "timestamp": obj.get('timestamp')
            }
            payload = json.dumps(msg)
            try:
                if MQTT_USER:
                    publish.single(MQTT_TOPIC, payload, hostname=MQTT_BROKER, auth={'username':MQTT_USER,'password':MQTT_PASS})
                else:
                    publish.single(MQTT_TOPIC, payload, hostname=MQTT_BROKER)
                print("Published:", payload)
            except Exception as e:
                print("MQTT publish failed:", e)

if __name__ == "__main__":
    main()
PY

chmod +x "$SNORT2MQTT_PATH"
chown root:root "$SNORT2MQTT_PATH"

echo "=== Create systemd service for snort2mqtt ==="
cat > /etc/systemd/system/snort2mqtt.service <<'SERVICE'
[Unit]
Description=Snort -> MQTT bridge service
After=network.target mosquitto.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/snort2mqtt.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now snort2mqtt.service

echo "=== (Optional) Provide example NodeMCU sketch file to upload to device ==="
NODEMCU_SKETCH="/usr/local/share/nodemcu_snippet.ino"
cat > "$NODEMCU_SKETCH" <<'INO'
/*
 NodeMCU example (Arduino) - subscribe to MQTT topic and trigger buzzer/LED
 Replace SSID, PASS, MQTT broker IP before upload.
*/
#include <ESP8266WiFi.h>
#include <PubSubClient.h>

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_WIFI_PASS";
const char* mqtt_server = "192.168.1.100"; // change to broker IP

WiFiClient espClient;
PubSubClient client(espClient);
const int BUZZER_PIN = D1;
const int LED_PIN = D2;

void callback(char* topic, byte* payload, unsigned int length) {
  String msg;
  for (unsigned int i=0;i<length;i++) msg += (char)payload[i];
  if (msg.length() > 0) {
    digitalWrite(LED_PIN, HIGH);
    digitalWrite(BUZZER_PIN, HIGH);
    delay(800);
    digitalWrite(LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
  }
}

void reconnect() {
  while (!client.connected()) {
    if (client.connect("NodeMCU-HIDS")) {
      client.subscribe("disdukcapil/snort/host-alerts");
    } else {
      delay(2000);
    }
  }
}

void setup() {
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
}

void loop() {
  if (!client.connected()) reconnect();
  client.loop();
}
INO

echo "=== Final checks & status ==="
echo "- Mosquitto status:"
systemctl status mosquitto --no-pager || true
echo "- Snort service is not auto-started by this script (snort may be configured to run as daemon depending on package)."
echo "- Ensure snort daemon is running and writing to: $EVE_JSON (or check /var/log/snort/)"

echo
echo "=== NEXT STEPS / NOTES ==="
cat <<EOS
1) Edit /etc/snort/rules/local.rules to adjust rules to your environment.
2) Edit /etc/snort/snort.conf if you need to tune HOME_NET or other vars.
   - For HIDS: set HOME_NET to the server's IP or local network as appropriate.
3) If your Snort package does NOT support 'output alert_json', the file /var/log/snort/eve.json might not be created.
   - Fallback: configure Snort unified2 output + install barnyard2 to convert to JSON, or adjust snort2mqtt.py to tail a plain-text alert file (/var/log/snort/alert) and parse lines.
4) Check snort logs: journalctl -u snort or /var/log/snort/* for errors.
5) Secure Mosquitto if exposing to other networks (create user with mosquitto_passwd, enable ACL/TLS).
6) If you prefer Snort 3 (from source), let me know; I can provide a build script (longer).
EOS

echo "=== DONE ==="

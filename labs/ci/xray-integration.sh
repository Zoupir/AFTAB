#!/usr/bin/env bash
# Real Xray integration test. Runs exclusively on an ephemeral GitHub runner.
# Never point this script at any user's VPS or an existing Xray/3x-ui instance.
set -Eeuo pipefail
IMAGE='ghcr.io/xtls/xray-core:26.10.21@sha256:447ffc750a0b87d6e4f2c38425f68105bfc8c789e59c22d83b94eb7e1e648c50'
WORK="$(mktemp -d)"
NAME="aftab-xray-ci-$$"
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
chmod 700 "$WORK"
echo "Pulling pinned upstream Xray integration-test image"
docker pull --platform linux/amd64 "$IMAGE" >/dev/null
# Keys exist only in process memory and the runner's private temp directory.
KEYOUTPUT="$(docker run --rm --platform linux/amd64 --network none "$IMAGE" x25519)"
export KEYOUTPUT WORK
python3 - <<'PY'
import json, os, re, socket
raw=os.environ['KEYOUTPUT']
values={}
for line in raw.splitlines():
    if ':' not in line:continue
    key,val=line.split(':',1)
    values[key.lower().replace(' ','').split('(')[0].strip()]=val.strip()
private=values.get('privatekey')
public=values.get('password') or values.get('publickey')
if not private or not public:
    raise SystemExit('Unsupported xray x25519 output: keys not detected')
def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]
api_port=free_port()
inbound_port=free_port()
while inbound_port==api_port:inbound_port=free_port()
config={
  'log':{'loglevel':'warning'},
  'api':{'tag':'api','listen':f'127.0.0.1:{api_port}','services':['HandlerService','StatsService']},
  'inbounds':[{
     'listen':'127.0.0.1',
     'port':inbound_port,
     'tag':'aftab-ci-reality',
     'protocol':'vless',
     'settings':{'clients':[],'decryption':'none'},
     'streamSettings':{
        'network':'tcp','security':'reality',
        'realitySettings':{
            'dest':'www.microsoft.com:443',
            'serverNames':['www.microsoft.com'],
            'privateKey':private,
            'shortIds':['0a12']
        }
      }
  }],
  'outbounds':[{'tag':'direct','protocol':'freedom'}]
}
with open(os.path.join(os.environ['WORK'],'config.json'),'w') as f:json.dump(config,f)
with open(os.path.join(os.environ['WORK'],'test-env'),'w') as f:
    f.write(f'AFTAB_TEST_XRAY_API=127.0.0.1:{api_port}\n')
    f.write('AFTAB_TEST_XRAY_INBOUND=aftab-ci-reality\n')
os.chmod(os.path.join(os.environ['WORK'],'config.json'),0o600)
print('Ephemeral Xray configuration prepared: no external listener')
PY
echo "Starting isolated Xray with REALITY inbound bound to loopback"
docker run -d --rm --platform linux/amd64 --network host --name "$NAME" --memory=300m --cpus=1.5 \
  --security-opt no-new-privileges --cap-drop ALL --read-only \
  -v "$WORK/config.json:/etc/xray/config.json:ro" "$IMAGE" run -c /etc/xray/config.json >/dev/null
set -a
# shellcheck disable=SC1091
source "$WORK/test-env"
set +a
for i in {1..40}; do
  if (echo >/dev/tcp/127.0.0.1/"${AFTAB_TEST_XRAY_API#*:}") 2>/dev/null; then break; fi
  if ! docker inspect "$NAME" >/dev/null 2>&1; then echo "Xray process exited";exit 1;fi
  sleep 0.5
done
if ! (echo >/dev/tcp/127.0.0.1/"${AFTAB_TEST_XRAY_API#*:}") 2>/dev/null;then
  echo "Xray API not ready"; docker logs "$NAME" | tail -30; exit 1
fi
echo "Run LIVE panel → agent → Xray HandlerService AddUser/GetInboundUsers/RemoveUser test"
go test -race -count=1 -timeout=60s -run TestLiveXrayProvisioningLifecycle ./cmd/panel
echo "AFTAB_LIVE_XRAY_INTEGRATION_OK"

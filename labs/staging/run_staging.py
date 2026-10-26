#!/usr/bin/env python3
"""AFTAB local disposable staging smoke test. Does NOT touch the VPS or 3x-ui.
Tested with CI artifacts at 2026-10-26. Uses short-lived loopback-only processes.
Outputs only sanitized test results; never stores secrets in report.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def assert_ok(case, passed, detail, results):
    results.append({'check': case, 'result': 'PASS' if passed else 'FAIL', 'detail': detail})
    if not passed:
        raise AssertionError(f'{case}: {detail}')


def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def http_call(port, path, method='GET', data=None, headers=None):
    body = None if data is None else json.dumps(data).encode()
    h = {'Content-Type':'application/json'} if data is not None else {}
    h.update(headers or {})
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=body, method=method, headers=h)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=3) as r:
            return r.status, r.read(8192), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(8192), e.headers


def await_health(port, path, proc, wait=9):
    start=time.monotonic()
    while time.monotonic()-start < wait:
        if proc.poll() is not None:
            return False
        try:
            status,_,_ = http_call(port,path)
            if status == 200:
                return True
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.12)
    return False


def terminate(p):
    if not p:return
    if p.poll() is not None:return
    p.terminate()
    try: p.wait(timeout=4)
    except subprocess.TimeoutExpired: p.kill();p.wait(timeout=4)


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument('--artifacts',type=pathlib.Path,default=pathlib.Path('/mnt/data/aftab-ci-verified'))
    cli.add_argument('--output',type=pathlib.Path,default=pathlib.Path('/mnt/data/aftab-staging-step1/report.json'))
    a=cli.parse_args()
    results=[]; procs=[];errors=[]
    root=a.artifacts.resolve()
    files=('aftab-linux-amd64','aftab-panel-linux-amd64','aftab-agent-linux-amd64','aftab-server-amd64.deb')
    try:
        sums={}
        for line in (root/'SHA256SUMS.txt').read_text().splitlines():
            parts=line.strip().split()
            if len(parts)==2:sums[parts[1].lstrip('*')]=parts[0]
        for f in files:
            digest=hashlib.sha256((root/f).read_bytes()).hexdigest()
            assert_ok(f'Build integrity: {f}',f in sums and digest==sums[f],'sha256 matches verified GitHub Actions artifact',results)
        with tempfile.TemporaryDirectory(prefix='aftab-isolated-') as t:
            temp=pathlib.Path(t)
            temp.chmod(0o700)
            extract=temp/'debroot';extract.mkdir()
            unpack=subprocess.run(['dpkg-deb','--extract',str(root/'aftab-server-amd64.deb'),str(extract)],capture_output=True,text=True,timeout=15)
            embedded=extract/'usr/bin/aftab-server'
            assert_ok('Debian package extraction',unpack.returncode==0 and embedded.exists(),'unpacked in disposable directory, no apt/dpkg installation',results)
            assert_ok('Debian binary integrity',hashlib.sha256(embedded.read_bytes()).digest()==hashlib.sha256((root/'aftab-linux-amd64').read_bytes()).digest(),'Debian gateway identical to verified Linux executable',results)
            cert=temp/'local.crt'; key=temp/'local.key'
            certgen=subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1', '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost'],capture_output=True,text=True,timeout=15)
            assert_ok('Ephemeral TLS material',certgen.returncode==0 and cert.exists() and key.exists(),'test-only self-signed certificate, not for production',results)
            admin=unused_port();gateway=unused_port();panel=unused_port()
            logg=(temp/'gateway.log').open('wb');logp=(temp/'panel.log').open('wb')
            p1=subprocess.Popen([str(embedded),'-mode','server','-listen',f'127.0.0.1:{gateway}','-admin',f'127.0.0.1:{admin}','-db',str(temp/'gateway-users.json'),'-cert',str(cert),'-key',str(key)],cwd=temp,stdin=subprocess.DEVNULL,stdout=logg,stderr=subprocess.STDOUT)
            procs.append(p1)
            p2=subprocess.Popen([str(root/'aftab-panel-linux-amd64'),'-listen',f'127.0.0.1:{panel}','-db',str(temp/'stage-panel.sqlite')],env={**os.environ,'AFTAB_ADMIN_TOKEN':secrets.token_urlsafe(48)},cwd=temp,stdin=subprocess.DEVNULL,stdout=logp,stderr=subprocess.STDOUT)
            procs.append(p2)
            assert_ok('Gateway dashboard startup',await_health(admin,'/',p1),'temporary HTTP dashboard listening on loopback',results)
            assert_ok('Control panel startup',await_health(panel,'/health',p2),'SQLite control panel responds with HTTP 200 on loopback',results)
            status,body,headers=http_call(panel,'/health')
            assert_ok('Panel health JSON',status==200 and json.loads(body).get('status')=='ok','/health reports ok',results)
            status,_,_=http_call(panel,'/api/v1/users')
            assert_ok('Admin API rejects unauthenticated access',status==401,'HTTP 401 without bearer token',results)
            # secrets never leave the local temporary process/test
            # Since the panel token was passed directly at launch, read it from process environment isn't necessary.
            # The env passed to Popen is saved in memory below instead for convenience.
            terminate(p2);procs.remove(p2)
            panel_token=secrets.token_urlsafe(48)
            p2=subprocess.Popen([str(root/'aftab-panel-linux-amd64'),'-listen',f'127.0.0.1:{panel}','-db',str(temp/'stage-panel.sqlite')],env={**os.environ,'AFTAB_ADMIN_TOKEN':panel_token},cwd=temp,stdin=subprocess.DEVNULL,stdout=logp,stderr=subprocess.STDOUT)
            procs.append(p2)
            assert_ok('Panel secure restart',await_health(panel,'/health',p2),'restart with explicitly retained secret and SQLite database',results)
            auth={'Authorization':'Bearer '+panel_token}
            status,body,_=http_call(panel,'/api/v1/users',headers=auth)
            assert_ok('Authenticated account list',status==200 and isinstance(json.loads(body),list),'admin list readable',results)
            payload={'Name':'staging-test','Device':'windows','Days':1,'GB':1}
            status,body,_=http_call(panel,'/api/v1/users',method='POST',data=payload,headers=auth)
            account=json.loads(body) if body else {}
            assert_ok('Staging account created',status==201 and account.get('provisioning')=='pending_agent_configuration','created as pending without claiming Xray provisioning',results)
            status,body,_=http_call(panel,'/api/v1/users',headers=auth)
            assert_ok('Account persisted to SQLite',status==200 and len(json.loads(body))==1,'SQLite account list contains the test account',results)
            # Verify the same existing account remains after actual server restart.
            terminate(p2); procs.remove(p2)
            p2=subprocess.Popen([str(root/'aftab-panel-linux-amd64'),'-listen',f'127.0.0.1:{panel}','-db',str(temp/'stage-panel.sqlite')],env={**os.environ,'AFTAB_ADMIN_TOKEN':panel_token},cwd=temp,stdin=subprocess.DEVNULL,stdout=logp,stderr=subprocess.STDOUT)
            procs.append(p2)
            restarted=await_health(panel,'/health',p2)
            status,body,_=http_call(panel,'/api/v1/users',headers=auth)
            assert_ok('SQLite account survives panel restart',restarted and status==200 and len(json.loads(body))==1,'account is present after process restart with same SQLite database',results)
            status,body,_=http_call(panel,'/s/nonexistent-test-token')
            assert_ok('Subscription disabled without Agent',status==503,'no live Agent or Xray configured',results)
            # TLS1.3 handshake on gateway listener.
            ctx=ssl.create_default_context();ctx.load_verify_locations(cafile=str(cert));ctx.check_hostname=False;ctx.minimum_version=ssl.TLSVersion.TLSv1_3
            with socket.create_connection(('127.0.0.1',gateway), timeout=3) as s:
                with ctx.wrap_socket(s,server_hostname='localhost') as tls:
                    version=tls.version()
                    tls.sendall(b'invalid_staging_token\n')
            assert_ok('TLS gateway handshake',version=='TLSv1.3','TLS 1.3 established with short-lived local cert',results)
            # AFTAB should refuse any nonloopback admin/server bind.
            bad=subprocess.run([str(root/'aftab-panel-linux-amd64'),'-listen','0.0.0.0:19991','-db',str(temp/'should-not-exist.sqlite')],env={**os.environ,'AFTAB_ADMIN_TOKEN':panel_token},cwd=temp,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)
            assert_ok('Public panel binding denied',bad.returncode!=0 and b'loopback' in bad.stdout.lower(),'panel must reject 0.0.0.0',results)
            bad2=subprocess.run([str(embedded),'-mode','server','-listen','0.0.0.0:19992','-admin','127.0.0.1:19993','-db',str(temp/'badgateway.json')],cwd=temp,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)
            assert_ok('Public gateway binding denied',bad2.returncode!=0 and b'loopback' in bad2.stdout.lower(),'gateway must reject public bind',results)
            for p in procs[::-1]:terminate(p)
            procs=[]
            assert_ok('Isolated services cleanly stopped',p1.poll() is not None and p2.poll() is not None,'staging processes stopped; temporary keys and SQLite data destroyed on exit',results)
            logg.close();logp.close()
    except Exception as e:
        errors.append(f'{type(e).__name__}: {str(e)}')
    finally:
        for p in procs[::-1]:terminate(p)
    report={
      'project':'AFTAB', 'task':'Step 1: ephemeral isolated staging setup',
      'timestamp_utc':datetime.now(timezone.utc).isoformat(),
      'source_ci_head':os.getenv('GITHUB_SHA','eef4fc5d7622c411a4537253c0be1d2ced445727'),
      'source_ci_run_url':('https://github.com/Zoupir/AFTAB/actions/runs/'+os.environ['GITHUB_RUN_ID']) if os.getenv('GITHUB_RUN_ID') else 'https://github.com/Zoupir/AFTAB/actions/runs/40352514606',
      'staging_scope':'disposable local or GitHub-hosted runner, loopback only; not a permanent VPS',
      'private_vps_changed':False,'xray_or_3x_ui_changed':False,
      'agent_integration_live':False,'gateway_publicly_reachable':False,
      'checks':results,'summary':{'passed':sum(x['result']=='PASS' for x in results),'failed':sum(x['result']=='FAIL' for x in results)+len(errors)},
      'errors':errors
    }
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'summary':report['summary'],'checks':results,'errors':errors},ensure_ascii=False,indent=2))
    raise SystemExit(0 if not errors and report['summary']['failed']==0 else 1)

if __name__=='__main__':main()
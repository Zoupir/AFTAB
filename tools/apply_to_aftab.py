#!/usr/bin/env python3
"""Apply quota + restart recovery to a LOCAL checkout of next/orchestration-v1.

Does not connect to a VPS, SSH, or install daemons. Defaults to --dry-run.
Does not edit any original path when a required source anchor is missing.
"""
from pathlib import Path
import argparse
import shutil
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent.parent
FILES = (
    'internal/metering/metering.go',
    'internal/metering/metering_test.go',
    'internal/metering/reconciler.go',
    'internal/metering/reconciler_test.go',
    'internal/controlplane/store_metering.go',
    'internal/controlplane/store_metering_test.go',
    'internal/controlplane/store_provisioning.go',
    'internal/controlplane/store_provisioning_test.go',
    'internal/agenthttp/traffic.go',
    'internal/agenthttp/traffic_test.go',
    'internal/agenthttp/identity.go',
    'internal/agenthttp/identity_test.go',
    'internal/xrayapi/stats.go',
    'internal/xrayapi/stats_test.go',
    'internal/provisioning/reconcile.go',
    'internal/provisioning/reconcile_test.go',
    'internal/nodeconfig/validate.go',
    'internal/nodeconfig/validate_test.go',
    'tools/apply_to_aftab.py',
    'tools/test_apply_to_aftab.py',
    'docs/INTEGRATION-STATUS-FA.md',
)


def replace_once(text, needle, replacement, filename):
    count = text.count(needle)
    if count != 1:
        raise ValueError(f'{filename}: expected 1 matching code anchor, found {count}')
    return text.replace(needle, replacement, 1)


def make_updates(original):
    panel = original['cmd/panel/main.go']
    agent = original['internal/agenthttp/agent.go']
    xray = original['internal/xrayapi/client.go']
    agentcli = original['cmd/agent/main.go']
    workflow = original['.github/workflows/build.yml']

    panel = replace_once(panel, ' "crypto/subtle"', ' "crypto/subtle"\n "context"\n "sync"', 'cmd/panel/main.go')
    panel = replace_once(panel, ' "github.com/Zoupir/AFTAB/internal/controlplane"',
        ' "github.com/Zoupir/AFTAB/internal/controlplane"\n "github.com/Zoupir/AFTAB/internal/metering"\n "github.com/Zoupir/AFTAB/internal/provisioning"', 'cmd/panel/main.go')
    if ' node *subscription.RealityNode\n}' in panel:
        panel = replace_once(panel, ' node *subscription.RealityNode\n}',
             ' node *subscription.RealityNode\n lifecycle *sync.Mutex\n}', 'cmd/panel/main.go')
    else:
        panel = replace_once(panel, ' agent *agenthttp.LocalClient\n}',
             ' agent *agenthttp.LocalClient\n lifecycle *sync.Mutex\n}', 'cmd/panel/main.go')
    panel = replace_once(panel, 'func (a *api)ServeHTTP(w http.ResponseWriter,r *http.Request){',
      '''func (a *api)ServeHTTP(w http.ResponseWriter,r *http.Request){
 // Serialize admin mutations against metering/restoration to avoid reviving
 // an account while its creation or cancellation is only half committed.
 if a.lifecycle!=nil && r.Method==http.MethodPost && strings.HasPrefix(r.URL.Path,"/api/v1/users") {
  a.lifecycle.Lock()
  defer a.lifecycle.Unlock()
 }''', 'cmd/panel/main.go')
    panel = replace_once(panel, ' defer s.Close()\n var agent *agenthttp.LocalClient',
        ' defer s.Close()\n if e:=s.EnsureMeteringSchema(context.Background());e!=nil{log.Fatal(e)}\n var agent *agenthttp.LocalClient', 'cmd/panel/main.go')
    insert = ''' var guard sync.Mutex
 if agent!=nil {
  restore:=provisioning.Reconciler{Store:s,Engine:*agent}
  meter:=metering.Reconciler{Store:s,Engine:*agent}
  go func(){
   ticker:=time.NewTicker(10*time.Second)
   defer ticker.Stop()
   for {
    guard.Lock()
    now:=time.Now().UTC()
    if _,e:=restore.RunOnce(context.Background(),now);e!=nil{
     log.Printf("AFTAB recovery failed; next cycle will retry: %v",e)
    }
    if e:=meter.RunOnce(context.Background(),now);e!=nil{
     log.Printf("AFTAB metering failed; next cycle will retry: %v",e)
    }
    guard.Unlock()
    <-ticker.C
   }
  }()
 }
'''
    panel = replace_once(panel, ' srv:=&http.Server{', insert+' srv:=&http.Server{', 'cmd/panel/main.go')
    panel = replace_once(panel, 'adminToken:secret,agent:agent,node:node}',
         'adminToken:secret,agent:agent,node:node,lifecycle:&guard}', 'cmd/panel/main.go')

    traffic_route = ''' if strings.HasPrefix(r.URL.Path,"/v1/users/")&&strings.HasSuffix(r.URL.Path,"/traffic")&&r.Method=="GET"{
  id:=strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,"/v1/users/"),"/traffic")
  if len(id)!=36||strings.ContainsAny(id,"/\\\\"){output(w,404,map[string]string{"error":"not_found"});return}
  engine,ok:=h.Engine.(TrafficEngine)
  if !ok{output(w,503,map[string]string{"error":"stats_unavailable"});return}
  counters,e:=engine.UserTraffic(ctx,id)
  if e!=nil{output(w,502,map[string]string{"error":"stats_query_failed"});return}
  output(w,200,map[string]int64{"uplink":counters.Uplink,"downlink":counters.Downlink});return
 }
'''
    identity_route = ''' if strings.HasPrefix(r.URL.Path,"/v1/users/")&&strings.HasSuffix(r.URL.Path,"/identity")&&r.Method=="GET"{
  id:=strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,"/v1/users/"),"/identity")
  if len(id)!=36||strings.ContainsAny(id,"/\\\\"){output(w,404,map[string]string{"error":"not_found"});return}
  engine,ok:=h.Engine.(IdentityEngine)
  if !ok{output(w,503,map[string]string{"error":"identity_unavailable"});return}
  uuid,found,e:=engine.GetUserUUID(ctx,id)
  if e!=nil{output(w,502,map[string]string{"error":"identity_query_failed"});return}
  output(w,200,map[string]any{"uuid":uuid,"found":found});return
 }
'''
    agent=replace_once(agent,
        ' if strings.HasPrefix(r.URL.Path,"/v1/users/")&&strings.HasSuffix(r.URL.Path,"/disable")',
        traffic_route+identity_route+' if strings.HasPrefix(r.URL.Path,"/v1/users/")&&strings.HasSuffix(r.URL.Path,"/disable")',
        'internal/agenthttp/agent.go')
    # Xray can reply with gRPC NotFound if a specific user does not exist.
    # This is a verified absent peer, distinct from an unavailable API.
    xray=replace_once(xray,' "google.golang.org/grpc/credentials/insecure"',
        ' "google.golang.org/grpc/credentials/insecure"\n "google.golang.org/grpc/codes"\n "google.golang.org/grpc/status"', 'internal/xrayapi/client.go')
    xray=replace_once(xray,' if e!=nil{return "",false,e}\n users,e:=readBytesField(response,1)',
        ' if status.Code(e)==codes.NotFound{return "",false,nil}\n if e!=nil{return "",false,e}\n users,e:=readBytesField(response,1)', 'internal/xrayapi/client.go')
    agentcli=replace_once(agentcli,
        ' "github.com/Zoupir/AFTAB/internal/xrayapi"',
        ' "github.com/Zoupir/AFTAB/internal/xrayapi"\n "github.com/Zoupir/AFTAB/internal/nodeconfig"',
        'cmd/agent/main.go')
    agentcli=replace_once(agentcli,
        ' if e:=xrayapi.ValidateClient(engine);e!=nil{log.Fatal(e)}',
        ''' if e:=xrayapi.ValidateClient(engine);e!=nil{log.Fatal(e)}
 configPath:=os.Getenv("AFTAB_XRAY_CONFIG")
 if configPath==""{log.Fatal("AFTAB_XRAY_CONFIG is required for quota-enabled agent")}
 raw,e:=os.ReadFile(configPath)
 if e!=nil{log.Fatal("cannot read dedicated Xray node configuration: ",e)}
 if e=nodeconfig.VerifyRuntimeConfig(raw,*inbound);e!=nil{log.Fatal("Xray stats safety check failed: ",e)}''',
        'cmd/agent/main.go')
    workflow=replace_once(workflow,
        '      - name: Static analysis\n        run: go vet ./...\n',
        '      - name: Validate Stage 1 integration tool\n        run: python3 -m unittest discover -s tools -p test_apply_to_aftab.py -v\n'
        '      - name: Static analysis\n        run: go vet ./...\n',
        '.github/workflows/build.yml')
    return {'cmd/panel/main.go':panel,'internal/agenthttp/agent.go':agent,'internal/xrayapi/client.go':xray,'cmd/agent/main.go':agentcli,'.github/workflows/build.yml':workflow}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('repo',type=Path,help='local AFTAB source tree, never a live VPS')
    parser.add_argument('--apply',action='store_true',help='write only after validating the source anchors')
    args=parser.parse_args()
    root=args.repo.resolve()
    needed=('cmd/panel/main.go','internal/agenthttp/agent.go','internal/xrayapi/client.go','cmd/agent/main.go','internal/controlplane/store.go','.github/workflows/build.yml')
    missing=[x for x in needed if not (root/x).is_file()]
    if missing:sys.exit('STOP: missing AFTAB branch files: '+', '.join(missing))
    if not (root/'.git').exists():
        sys.exit('STOP: target must be an actual Git checkout, not an arbitrary directory')
    def git(*args):
        return subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True)
    branch = git('branch', '--show-current')
    if branch.returncode or branch.stdout.strip() != 'next/orchestration-v1':
        sys.exit('STOP: required Git branch is next/orchestration-v1')
    remote = git('remote', 'get-url', 'origin')
    allowed = ('https://github.com/Zoupir/AFTAB.git',
               'https://github.com/Zoupir/AFTAB',
               'git@github.com:Zoupir/AFTAB.git')
    if remote.returncode or remote.stdout.strip() not in allowed:
        sys.exit('STOP: checkout origin is not Zoupir/AFTAB')
    status = git('status', '--porcelain', '--untracked-files=all')
    if status.returncode or status.stdout.strip():
        sys.exit('STOP: checkout has uncommitted changes; do not overwrite local work')
    originals={x:(root/x).read_text(encoding='utf-8') for x in needed if x!='internal/controlplane/store.go'}
    try:updated=make_updates(originals)
    except ValueError as e:sys.exit('STOP: code anchors differ; nothing changed: '+str(e))
    collisions=[x for x in FILES if (root/x).exists()]
    if collisions:sys.exit('STOP: files already exist; compare versions: '+', '.join(collisions))
    overlay={x:(PACKAGE/x).read_bytes() for x in FILES}
    overlay.update({x:b.encode('utf-8') for x,b in updated.items()})
    print('AFTAB quota/recovery overlay verified; paths:',*overlay.keys(),sep='\n  ')
    if not args.apply:
        print('DRY-RUN ONLY: no changes made. Specify --apply to modify checkout.')
        return
    # Backups are deliberately stored as private sibling directory, OUTSIDE
    # the Git checkout. A "git add ." must never include restored preimages.
    backup_dir = root.parent / ('.aftab-stage1-backup-' + root.name)
    if backup_dir.exists() or backup_dir.is_symlink():
        sys.exit('STOP: existing external integration backup: ' + str(backup_dir))
    # Refuse symbolic links along all modified paths. Following an arbitrary
    # checkout symlink could overwrite files outside the repository.
    for name in overlay:
        dest = root / name
        path = dest
        while path != root:
            if path.is_symlink():
                sys.exit('STOP: symlink in modified path: ' + str(path))
            path = path.parent
        temp = dest.with_name(dest.name + '.aftab-tmp')
        if temp.exists() or temp.is_symlink():
            sys.exit('STOP: temporary output path already exists: ' + str(temp))
    # Recheck source content to guard against concurrent changes.
    for name in originals:
        if (root / name).read_text(encoding='utf-8') != originals[name]:
            sys.exit('STOP: checkout changed during preflight: ' + name)
    # Keep rollback source copies independent from checkout. The directory is
    # created with restrictive permissions before writing any user bytes.
    backed=[]
    made=[]
    temps=[]
    try:
        backup_dir.mkdir(mode=0o700)
        for name in updated:
            source = root / name
            backup = backup_dir / name
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, backup)
            backed.append(name)
        for name,content in overlay.items():
            dest=root/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            temp=dest.with_name(dest.name+'.aftab-tmp')
            # Exclusive creation avoids clobbering a path materialized after
            # preflight but before this individual file write.
            with temp.open('xb') as handle:
                handle.write(content)
            temps.append(temp)
            temp.replace(dest)
            temps.pop()
            made.append(name)
        print('Applied locally. Protected backups stored OUTSIDE Git:', backup_dir)
        print('Before any deployment: gofmt -w; go test -race ./...; review diff and CI.')
    except Exception:
        for temp in temps:
            temp.unlink(missing_ok=True)
        for name in reversed(made):
            dest=root/name
            if name in originals:
                # Restore the original source bytes, including file mode.
                shutil.copy2(backup_dir/name, dest)
            else:
                dest.unlink(missing_ok=True)
        # Do not discard backups if rollback itself has failed unexpectedly.
        if all((root/name).read_text(encoding='utf-8') == originals[name] for name in originals):
            shutil.rmtree(backup_dir)
        raise

if __name__=='__main__':main()

#!/usr/bin/env python3
"""Regression checks for the safe, offline AFTAB Stage 1 overlay tool.

Uses disposable fixture checkout; not a substitute for the real branch CI.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / 'tools' / 'apply_to_aftab.py'

FIXTURE = {
    'cmd/panel/main.go': '''package main
import (\n "crypto/subtle"\n "github.com/Zoupir/AFTAB/internal/controlplane"\n)
type api struct {\n agent *agenthttp.LocalClient\n}
func (a *api)ServeHTTP(w http.ResponseWriter,r *http.Request){\n}
func main(){\n defer s.Close()\n var agent *agenthttp.LocalClient\n srv:=&http.Server{Addr:*addr,Handler:&api{users:s,adminToken:secret,agent:agent,node:node}}\n}
''',
    'internal/agenthttp/agent.go': '''package agenthttp
func (h *Handler)ServeHTTP(w http.ResponseWriter,r *http.Request){
 if strings.HasPrefix(r.URL.Path,"/v1/users/")&&strings.HasSuffix(r.URL.Path,"/disable") {\n}\n}\n''',
    'internal/xrayapi/client.go': '''package xrayapi
import (\n "google.golang.org/grpc/credentials/insecure"\n)
func (c Client)GetUserUUID(ctx context.Context,id string)(string,bool,error){\n if e!=nil{return "",false,e}\n users,e:=readBytesField(response,1)\n}\n''',
    'cmd/agent/main.go': '''package main
import (\n "github.com/Zoupir/AFTAB/internal/xrayapi"\n)
func main(){\n if e:=xrayapi.ValidateClient(engine);e!=nil{log.Fatal(e)}\n}\n''',
    'internal/controlplane/store.go': 'package controlplane\n',
    '.github/workflows/build.yml': 'name: CI\njobs:\n  build:\n    steps:\n      - name: Static analysis\n        run: go vet ./...\n',
}


def run(target, apply=False):
    args = [sys.executable, str(TOOL), str(target)]
    if apply:
        args.append('--apply')
    return subprocess.run(args, text=True, capture_output=True, check=False)


class ApplyOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aftab-stage1-test-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'checkout'
        for name, text in FIXTURE.items():
            dest = self.repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding='utf8')
        def init(*args):
            done = subprocess.run(['git','-C',str(self.repo),*args], capture_output=True, text=True)
            if done.returncode:raise RuntimeError(done.stderr)
        init('init','-b','next/orchestration-v1')
        init('config','user.name','Stage1 Self-Test')
        init('config','user.email','stage1@example.invalid')
        init('remote','add','origin','https://github.com/Zoupir/AFTAB.git')
        init('add','.')
        init('commit','-m','Synthetic offline fixture')

    def test_dry_run_makes_no_changes(self):
        original = (self.repo / 'cmd/panel/main.go').read_bytes()
        result = run(self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('DRY-RUN ONLY', result.stdout)
        self.assertEqual((self.repo / 'cmd/panel/main.go').read_bytes(), original)
        self.assertFalse((self.repo / 'internal/metering/reconciler.go').exists())

    def test_apply_creates_new_sources_and_backups(self):
        result = run(self.repo, True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.repo / 'internal/metering/reconciler.go').exists())
        self.assertTrue((self.repo.parent / ('.aftab-stage1-backup-' + self.repo.name) / 'cmd/panel/main.go').exists())
        panel = (self.repo / 'cmd/panel/main.go').read_text()
        self.assertIn('EnsureMeteringSchema', panel)
        self.assertIn('lifecycle:&guard', panel)
        self.assertIn('provisioning.Reconciler', panel)
        self.assertIn('metering.Reconciler', panel)
        self.assertEqual(len(list((self.repo.parent / ('.aftab-stage1-backup-' + self.repo.name)).rglob('*.go')))+len(list((self.repo.parent / ('.aftab-stage1-backup-' + self.repo.name)).rglob('*.yml'))), 5)
        self.assertFalse(list(self.repo.rglob('*.bak')))
        self.assertFalse(list(self.repo.rglob('*.aftab-tmp')))
        self.assertIn('Validate Stage 1 integration tool', (self.repo/'.github/workflows/build.yml').read_text())

    def test_rejects_symlink_source_without_writing(self):
        original = self.repo/'cmd/panel/main.go'
        target = Path(self.temp.name)/'outside.go'
        target.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(target)
        result = run(self.repo, True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('STOP:', result.stdout + result.stderr)
        self.assertEqual(target.read_bytes(), FIXTURE['cmd/panel/main.go'].encode())

    def test_rejects_preexisting_external_backup(self):
        folder = self.repo.parent / ('.aftab-stage1-backup-' + self.repo.name)
        folder.mkdir()
        result = run(self.repo, True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('existing external integration backup', result.stdout + result.stderr)

    def test_no_backup_files_inside_checkout_after_apply(self):
        result = run(self.repo, True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        changed = subprocess.run(['git','-C',str(self.repo),'status','--porcelain','--untracked-files=all'],capture_output=True,text=True,check=True).stdout
        self.assertNotIn('aftab-before-v2.bak', changed)
        self.assertNotIn('aftab-stage1-backup-', changed)
        self.assertNotIn('.aftab-tmp', changed)

    def test_reapplying_fails_closed(self):
        first = run(self.repo, True)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = run(self.repo, True)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn('STOP:', second.stdout + second.stderr)

    def test_mismatched_anchor_does_not_write(self):
        p = self.repo / 'cmd/panel/main.go'
        p.write_text(p.read_text().replace('crypto/subtle', 'crypto/sha256'))
        subprocess.run(['git','-C',str(self.repo),'add','.'],check=True)
        subprocess.run(['git','-C',str(self.repo),'commit','-m','Simulate upstream change'],check=True,capture_output=True)
        original = p.read_bytes()
        result = run(self.repo, True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('code anchors differ', result.stdout + result.stderr)
        self.assertEqual(p.read_bytes(), original)
        self.assertFalse((self.repo / 'internal/metering/metering.go').exists())

    def test_refuses_preexisting_overlay_collision(self):
        p = self.repo/'internal/metering/metering.go'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('// Local custom implementation that must not be overwritten\n')
        subprocess.run(['git','-C',str(self.repo),'add','.'],check=True)
        subprocess.run(['git','-C',str(self.repo),'commit','-m','Existing custom metering'],check=True,capture_output=True)
        result = run(self.repo,True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('files already exist',result.stdout+result.stderr)
        self.assertIn('must not be overwritten',p.read_text())

    def test_refuses_wrong_branch(self):
        res = subprocess.run(['git','-C',str(self.repo),'checkout','-b','main'],capture_output=True,text=True)
        self.assertEqual(res.returncode,0,res.stderr)
        result = run(self.repo, True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('required Git branch', result.stdout+result.stderr)

    def test_refuses_dirty_checkout(self):
        p=self.repo/'cmd/panel/main.go'
        p.write_text(p.read_text()+'\n// user modified\n')
        result=run(self.repo,True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('uncommitted changes',result.stdout+result.stderr)

    def test_refuses_wrong_origin(self):
        subprocess.run(['git','-C',str(self.repo),'remote','set-url','origin','https://github.com/another/repo.git'],check=True)
        result=run(self.repo,True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('not Zoupir/AFTAB',result.stdout+result.stderr)

    def test_refuses_non_checkout(self):
        import shutil
        shutil.rmtree(self.repo / '.git')
        result = run(self.repo, True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('STOP:', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

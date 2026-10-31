import tempfile,subprocess,json,importlib.util,os
from pathlib import Path
roots=[str(Path(__file__).resolve().parents[1])]
for project in roots:
 script=Path(project)/'scripts/migrate-paths.py';spec=importlib.util.spec_from_file_location('migrate',script);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 with tempfile.TemporaryDirectory(prefix='kagnode-migration-') as tmp:
  root=Path(tmp);journal=root/'journal.json'
  for old,new in mod.MAPPINGS:
   p=root/old.lstrip('/');p.mkdir(parents=True);p.chmod(0o750);(p/'sample').write_text(old);(p/'sample').chmod(0o640);(p/'link').symlink_to('sample')
  if mod.PROJECT=='mail':p=root/'opt/kagnode/kagnode';p.mkdir();(p/'web.py').write_text('# fixture')
  def call(*args,ok=True):
   out=subprocess.run(['python3',str(script),'--root',tmp,'--journal',str(journal),*args],text=True,capture_output=True)
   assert (out.returncode==0)==ok,out.stdout+out.stderr
   return out
  call();assert not journal.exists();call('--apply');call('--apply')
  for old,new in mod.MAPPINGS:
   assert (root/new.lstrip('/')/'sample').read_text()==old
   assert (root/old.lstrip('/')/'sample').read_text()==old
   assert (root/new.lstrip('/')).stat().st_mode&0o777==0o750
  data=json.loads(journal.read_text());record=data['records'][-1];record['stage']='copying';journal.write_text(json.dumps(data));call('--apply')
  for old,new in mod.MAPPINGS:(root/new.lstrip('/')/'after').write_text('post migration write')
  call('--rollback');call('--rollback');call('--apply',ok=False)
  for old,new in mod.MAPPINGS:assert (root/old.lstrip('/')/'sample').read_text()==old
  assert len(list(root.rglob('after')))==len(mod.MAPPINGS)
 print(mod.PROJECT,'apply/idempotence/resume/rollback/new writes/modes: passed')
# Reject unrelated data and destination conflicts without mutation.
for project in roots:
 script=Path(project)/'scripts/migrate-paths.py';spec=importlib.util.spec_from_file_location('migrate',script);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 with tempfile.TemporaryDirectory() as tmp:
  root=Path(tmp);old,new=mod.MAPPINGS[0];src=root/old.lstrip('/');src.mkdir(parents=True);(src/'keep').write_text('original');dst=root/new.lstrip('/');dst.mkdir(parents=True,exist_ok=True);(dst/'other').write_text('other project')
  out=subprocess.run(['python3',str(script),'--root',tmp,'--apply'],capture_output=True);assert out.returncode!=0;assert (src/'keep').read_text()=='original';assert (dst/'other').read_text()=='other project'
 print(mod.PROJECT,'conflict refusal: passed')

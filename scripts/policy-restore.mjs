import { readFile, lstat, mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const backup = resolve(root, 'backups/policy-stage9');
const hash = b => createHash('sha256').update(b).digest('hex');
try {
  const [folder, flag, confirmation, ...extra] = process.argv.slice(2);
  if (!folder || extra.length || (flag && (flag !== '--apply' || !confirmation))) throw new Error('사용법: node scripts/policy-restore.mjs 시험폴더 [--apply 확인값]');
  const trial = resolve(folder);
  // 적용 범위는 프로젝트 내부의 전용 시험 폴더로 고정합니다.
  if (trial !== resolve(root, '.trial-policy')) throw new Error('프로젝트의 .trial-policy 폴더만 복원할 수 있습니다.');
  for (const path of [trial, resolve(trial, 'src')]) {
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('시험 폴더 연결 또는 형식 오류');
  }
  const checked = spawnSync(process.execPath, [resolve(root,'scripts/policy-diff.mjs'),trial], {encoding:'utf8'});
  if (checked.status !== 0) throw new Error(checked.stderr.trim() || '사본 검증 실패');
  const plan = JSON.parse(checked.stdout);
  const token = hash(JSON.stringify(plan));
  console.log(JSON.stringify({...plan, confirmation:token}, null, 2));
  if (!flag) {
    console.log('표시된 변경 확인 후 같은 명령에 --apply 확인값을 붙이세요.');
  } else {
    if (confirmation !== token) throw new Error('확인값이 다르거나 시험 정책이 변경됐습니다. 미리보기를 다시 실행하세요.');
    const pending = [];
    for (const change of plan.changes) {
      if (!/^src\/[a-z0-9-]+\.mjs$/.test(change.path)) throw new Error('복원 경로 오류');
      const target = resolve(trial, change.path);
      if (!target.startsWith(trial+sep)) throw new Error('복원 범위 오류');
      try { if ((await lstat(target)).isSymbolicLink()) throw new Error('연결 파일 복원 금지'); }
      catch(e) { if (e.code !== 'ENOENT') throw e; }
      const bytes = await readFile(resolve(backup,change.path));
      if (hash(bytes) !== change.restoreSha256) throw new Error('사본 재검증 실패');
      pending.push({target,bytes});
    }
    for (const item of pending) { await mkdir(dirname(item.target),{recursive:true}); await writeFile(item.target,item.bytes); }
    const after = spawnSync(process.execPath,[resolve(root,'scripts/policy-diff.mjs'),trial],{encoding:'utf8'});
    if(after.status!==0 || JSON.parse(after.stdout).changedFiles!==0) throw new Error('복원 후 검증 실패');
    console.log(JSON.stringify({applied:true,restoredFiles:pending.length,verified:true,scope:'.trial-policy only'}));
  }
} catch(e) { console.error('시험 정책 복원 중단: '+e.message);process.exitCode=1; }

import { readFile, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const backup = resolve(root, 'backups/policy-stage9');
const PIN = '876eaabad702196418777ba8d1ace40d506d80800fce1064df60ae4e97a210a2';
const hash = b => createHash('sha256').update(b).digest('hex');
try {
  const args = process.argv.slice(2);
  if (args.length !== 1) throw new Error('사용법: node scripts/policy-diff.mjs 시험정책폴더');
  const trial = resolve(args[0]);
  if (trial === root || trial === backup || trial.startsWith(backup + '/')) throw new Error('별도 시험정책 폴더를 지정하세요.');
  const raw = await readFile(resolve(backup, 'manifest.json'));
  if (hash(raw) !== PIN) throw new Error('정책 사본 명세 검증 실패');
  const manifest = JSON.parse(raw);
  const changes = [];
  // 모든 사본 검증이 끝나기 전에는 차이를 출력하지 않습니다.
  for (const entry of manifest.files) {
    const original = await readFile(resolve(backup, entry.path));
    if (hash(original) !== entry.sha256) throw new Error('정책 사본 검증 실패: ' + entry.path);
  }
  for (const entry of manifest.files) {
    let current;
    try {
      const path = resolve(trial, entry.path);
      if (!(await lstat(path)).isFile()) throw new Error('일반 파일이 아님');
      current = hash(await readFile(path));
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      current = null;
    }
    if (current !== entry.sha256) changes.push({ path: entry.path, currentSha256: current, restoreSha256: entry.sha256 });
  }
  console.log(JSON.stringify({mode:'preview_only', backupVerified:true, restoreVersion:manifest.version,
    sourceCommit:manifest.sourceCommit, scope:'자료실 인증·접근 정책 파일만 비교; 다른 파일과 감사 이력 제외',
    changes, changedFiles:changes.length, applied:false}, null, 2));
} catch (e) {
  console.error('정책 비교 중단: ' + e.message);
  process.exitCode = 1;
}

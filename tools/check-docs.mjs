import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import process from 'node:process';

const root = resolve(import.meta.dirname, '..');
const ignoredDirectories = new Set(['.git', 'dist', 'node_modules']);
const errors = [];

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) {
      return ignoredDirectories.has(entry.name) ? [] : markdownFiles(join(directory, entry.name));
    }
    return extname(entry.name).toLowerCase() === '.md' ? [join(directory, entry.name)] : [];
  });
}

function report(file, line, message) {
  errors.push(`${relative(root, file)}:${line}: ${message}`);
}

function checkFormat(file, content) {
  const lines = content.split('\n');
  lines.forEach((line, index) => {
    if (/[ \t]+$/.test(line)) report(file, index + 1, '行尾包含多余空白');
    if (/^\t/.test(line)) report(file, index + 1, '请使用空格缩进 Markdown');
  });
  if (!content.endsWith('\n')) report(file, lines.length, '文件末尾缺少换行');
  if (content.endsWith('\n\n')) report(file, lines.length, '文件末尾存在多余空行');
}

function checkLocalLinks(file, content) {
  const linkPattern = /!?\[[^\]]*\]\(([^)]+)\)/g;
  for (const match of content.matchAll(linkPattern)) {
    const rawTarget = match[1].trim().replace(/^<|>$/g, '');
    if (!rawTarget || /^(?:https?:|mailto:|#)/i.test(rawTarget)) continue;
    const line = content.slice(0, match.index).split('\n').length;
    let target;
    try {
      target = decodeURIComponent(rawTarget.split('#')[0]);
    } catch {
      report(file, line, `链接编码无效：${rawTarget}`);
      continue;
    }
    if (!target || !existsSync(resolve(dirname(file), target))) {
      report(file, line, `本地链接不存在：${rawTarget}`);
    }
  }
}

const files = markdownFiles(root);
for (const file of files) {
  const content = readFileSync(file, 'utf8');
  checkFormat(file, content);
  checkLocalLinks(file, content);
}

const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const readme = readFileSync(join(root, 'README.md'), 'utf8');
for (const match of readme.matchAll(/npm run ([a-zA-Z0-9:_-]+)/g)) {
  if (!packageJson.scripts?.[match[1]]) {
    const line = readme.slice(0, match.index).split('\n').length;
    report(join(root, 'README.md'), line, `package.json 中不存在脚本：${match[1]}`);
  }
}

if (!statSync(join(root, 'README.md')).isFile()) errors.push('缺少 README.md');

if (errors.length > 0) {
  console.error(errors.join('\n'));
  process.exitCode = 1;
} else {
  console.log(`Documentation checks passed (${files.length} Markdown files).`);
}

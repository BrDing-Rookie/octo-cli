import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('CI includes tested Markdown and runs release workflow checks', () => {
  const source = read('.github/workflows/ci.yml');
  const push = source.split('  push:\n')[1]?.split('  pull_request:\n')[0] || '';
  assert.match(push, /\n    paths:\n/);
  for (const path of ['README.md', 'CHANGELOG.md']) {
    assert.ok(push.indexOf(`- '${path}'`) > push.indexOf("- '!*.md'"));
  }
  assert.match(source, /tested_docs:\n\s+- '\{README\.md,CHANGELOG\.md\}'/);
  const output = source.split('\n').find(line => line.trimStart().startsWith('code: ${{')) || '';
  assert.ok(output.includes("|| steps.filter.outputs.tested_docs == 'true'"));
  assert.match(source, /predicate-quantifier: 'every'/);
  assert.match(source, /run: node --test scripts\/release-workflows\.test\.mjs/);
});

test('local reusable workflows exist', () => {
  const workflows = new URL('../.github/workflows/', import.meta.url);
  for (const file of readdirSync(workflows).filter(file => /\.ya?ml$/.test(file))) {
    const source = readFileSync(new URL(file, workflows), 'utf8');
    // A removed local reusable workflow must not leave a dangling caller.
    for (const match of source.matchAll(/uses:\s*\.\/(\.github\/workflows\/[^\s]+\.ya?ml)/g)) {
      assert.ok(existsSync(new URL(`../${match[1]}`, import.meta.url)), `${file}: missing ${match[1]}`);
    }
  }
});

test('GitHub Release retains its CI gate and single-build publication ordering', () => {
  const source = read('.github/workflows/release-publish.yml');
  assert.match(source, /publish:\n\s+uses: Mininglamp-OSS\/\.github\/\.github\/workflows\/reusable-release-publish.yml@v1/);
  assert.match(source, /validate_run_id: \$\{\{ inputs.validate_run_id \}\}/);
  assert.match(source, /build:\n\s+needs: publish\n\s+if: \$\{\{ inputs.draft == false \}\}/);
  assert.match(source, /release-upload:\n\s+needs: \[publish, build\]/);
  assert.match(source, /publish-npm:\n\s+needs: \[publish, build, release-upload\]/);
  assert.match(source, /from_artifact: true/);
  assert.match(source, /NPM_TOKEN: \$\{\{ secrets.NPM_TOKEN \}\}/);
  assert.match(source, /cleanup-dist-artifact:\n\s+needs: \[build, release-upload, publish-npm\]/);
});

test('npm retains its release, CI, checksum, packaging and dry-run protections', () => {
  const source = read('.github/workflows/npm-publish.yml');
  assert.match(source, /workflow_call:/);
  assert.match(source, /workflow_dispatch:/);
  assert.match(source, /publish:\n\s+runs-on: ubuntu-latest/);
  for (const name of ['Verify release exists and is published', 'Verify CI evidence for the tagged commit']) {
    assert.ok(source.includes(`- name: ${name}\n        if: steps.version.outputs.DRY_RUN == ''`));
  }
  assert.match(source, /node --test scripts\/prepare-packages.test.js/);
  assert.match(source, /sha256sum --check "\$subset"/);
  assert.match(source, /inputs.from_artifact == true/);
  assert.match(source, /inputs.from_artifact != true/);
  assert.match(source, /NODE_AUTH_TOKEN: \$\{\{ steps.version.outputs.DRY_RUN == '' && secrets.NPM_TOKEN \|\| '' \}\}/);
  assert.match(source, /npm publish .* --dry-run/);
  assert.match(source, /cancel-in-progress: false/);
});

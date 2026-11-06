'use strict';

const { Octokit } = require('@octokit/rest');

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

const OWNER = 'solankiyashrajsinh922-cyber';
const REPO = 'loader-keys';

const FILES = {
  keys: 'keys.json',
  resellers: 'resellers.json',
  version: 'version.json',
  activity: 'activity.json',
};

const EMPTY = {
  'keys.json': {},
  'resellers.json': {},
  'version.json': {},
  'activity.json': { entries: [] },
};

async function read(path) {
  try {
    const { data } = await octokit.repos.getContent({ owner: OWNER, repo: REPO, path });
    const raw = Buffer.from(data.content || '', 'base64').toString('utf8') || '{}';
    return { data: JSON.parse(raw), sha: data.sha };
  } catch (err) {
    if (err.status !== 404) throw err;
    return create(path);
  }
}

async function create(path) {
  try {
    await octokit.repos.createOrUpdateFileContents({
      owner: OWNER,
      repo: REPO,
      path,
      message: `Init ${path}`,
      content: Buffer.from(JSON.stringify(EMPTY[path] || {}, null, 2)).toString('base64'),
    });
  } catch (err) {
    // Another request created it first, or the repo is read-only.
    if (err.status !== 409 && err.status !== 422) throw err;
  }
  const { data } = await octokit.repos.getContent({ owner: OWNER, repo: REPO, path });
  return { data: JSON.parse(Buffer.from(data.content, 'base64').toString('utf8')), sha: data.sha };
}

async function write(path, data, sha, message) {
  await octokit.repos.createOrUpdateFileContents({
    owner: OWNER,
    repo: REPO,
    path,
    message,
    content: Buffer.from(JSON.stringify(data, null, 2)).toString('base64'),
    ...(sha ? { sha } : {}),
  });
}

/**
 * Read the file, apply the mutator, write it back. Retries on sha conflicts.
 * Returning `false` from the mutator aborts without writing.
 */
async function mutate(path, mutator, message) {
  let lastErr;
  for (let attempt = 0; attempt < 4; attempt++) {
    const { data, sha } = await read(path);
    const result = await mutator(data);
    if (result === false) return { ok: false, data, result };
    try {
      await write(path, data, sha, message);
      return { ok: true, data, result };
    } catch (err) {
      lastErr = err;
      if (err.status !== 409 && err.status !== 422) throw err;
      await new Promise((r) => setTimeout(r, 120 * (attempt + 1)));
    }
  }
  throw lastErr || new Error('Write conflict');
}

module.exports = { read, mutate, FILES };

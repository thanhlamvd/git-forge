// git-forge: a GitHub-compatible git forge in one Node 22 process, stdlib only.
//
// Surfaces (all in-memory, deterministic, no git binary, no network):
//   - git smart HTTP: `/{owner}/{repo}.git` info/refs (v0 + v2) and git-upload-pack /
//     git-receive-pack, plus the same paths without the `.git` suffix (the suite uses both
//     spellings: info/refs under `/{owner}/{repo}` and the `.git` form for the smart
//     endpoints — both are served).
//   - REST v3 under /api/v3 (repos, branches, commits, contents, labels, issues, pulls).
//   - GraphQL v4 at /api/graphql (viewer, repository, issue, pullRequest, node, __type,
//     createIssue/closeIssue/createPullRequest/mergePullRequest/addComment, batching).
//   - MCP (Streamable HTTP, 2026-07-28 `server/discover` era, with the legacy
//     `initialize` handshake as a fallback) at /mcp.
//   - GET /healthz -> 200 {"ok":true}.
//
// Auth: every API call carries `Authorization: Bearer $MAKEFUN_SHOP_TOKEN`; the token
// names the fixed scenario viewer `adaiversen` (id 1000, from the kit's buildScenario()).
// A missing or wrong token is 401; the same repo name under another owner is 404 (never
// 403). The entry holds no state of its own across trials: every trial starts fresh.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// Constants: the fixed scenario (kit sdk/conformance/wire.ts buildScenario(), seed
// 0x6a09e667f3bcc909). The entry must know the viewer login from the fixed scenario because
// the bearer token does not encode it.
// -------------------------------------------------------------------------------------------

export const VIEWER = { id: 1000, login: 'adaiversen', name: 'ada iversen', email: 'adaiversen@example.invalid' };
export const TEAMMATE = { id: 1001, login: 'quinnkeller', name: 'quinn keller', email: 'quinnkeller@example.invalid' };
export const STRANGER = { id: 1002, login: 'olgabauer', name: 'olga bauer', email: 'olgabauer@example.invalid' };
export const ORG = 'faint-meadow-org';
export const DEFAULT_LABELS = ['bug', 'enhancement', 'documentation', 'question', 'good first issue', 'help wanted'];
export const DEFAULT_BRANCH = 'main';
export const ZERO_OID = '0000000000000000000000000000000000000000';
export const AGENT = 'git-forge/1.0.0';
export const INSTALLED_VERSION = '1.0.0';
// Deterministic clock base for every timestamp the forge itself mints (commits it creates,
// issues, comments, merges). A monotonic counter advances it so ordering is stable.
const EPOCH_SEC = 1735689600; // 2025-01-01T00:00:00Z
let clockSeq = 0;
function nextTimestamp(): number {
  clockSeq += 1;
  return EPOCH_SEC + clockSeq;
}
function isoOf(ts: number): string {
  return new Date(ts * 1000).toISOString();
}

// -------------------------------------------------------------------------------------------
// Small utilities
// -------------------------------------------------------------------------------------------

function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function sha1Hex(text: string): string {
  return createHash('sha1').update(text, 'utf8').digest('hex');
}
function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}
function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}
let requestSeq = 0;
function nextRequestId(): string {
  requestSeq += 1;
  return `req-${requestSeq.toString(16).padStart(8, '0')}-${sha1Hex(`${process.pid}:${requestSeq}`).slice(0, 12)}`;
}

// -------------------------------------------------------------------------------------------
// pkt-line framing (git wire protocol)
// -------------------------------------------------------------------------------------------

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLine(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, data]);
}
function pktText(text: string): Buffer {
  return pktLine(text);
}

type PktKind = 'data' | 'flush' | 'delim' | 'response-end';
interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

/** Decode a whole pkt-line stream into packets. Throws on a malformed frame. */
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len)) throw new Error('pkt-line length is not hex');
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('pkt-line length out of range');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

/** Split a sideband payload (band byte + data) into packets of at most `max` bytes. */
function sidebandPackets(band: number, data: Buffer, max = 65000): Buffer[] {
  const out: Buffer[] = [];
  if (data.length === 0) {
    out.push(pktLine(Buffer.concat([Buffer.from([band])])));
    return out;
  }
  for (let off = 0; off < data.length; off += max) {
    const chunk = data.subarray(off, Math.min(data.length, off + max));
    out.push(pktLine(Buffer.concat([Buffer.from([band]), chunk])));
  }
  return out;
}

// -------------------------------------------------------------------------------------------
// Git objects
// -------------------------------------------------------------------------------------------

export type ObjectType = 'blob' | 'tree' | 'commit' | 'tag';

export interface GitObject {
  type: ObjectType;
  data: Buffer;
}

function hashObject(type: ObjectType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([head, data]));
}

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd < 0 ? text : text.slice(0, headEnd);
  const message = headEnd < 0 ? '' : text.slice(headEnd + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const mode = data.subarray(off, sp).toString('utf8');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    out.push({ mode, name, oid });
    off = nul + 21;
  }
  return out;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface TagInfo {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagInfo {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd < 0 ? text : text.slice(0, headEnd);
  const message = headEnd < 0 ? '' : text.slice(headEnd + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

function identityLine(who: { name: string; email: string }, ts: number): string {
  return `${who.name} <${who.email}> ${ts} +0000`;
}

function buildCommit(tree: string, parents: string[], message: string, ts: number): Buffer {
  const lines: string[] = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${identityLine(VIEWER, ts)}`);
  lines.push(`committer ${identityLine(VIEWER, ts)}`);
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  return Buffer.from(`${lines.join('\n')}\n\n${msg}`, 'utf8');
}

/** Build a tree (and its subtrees) from a flat path -> {mode, oid} map. Returns the root tree oid. */
function buildTreeFromFiles(
  files: Map<string, { mode: string; oid: string }>,
  store: Map<string, GitObject>,
): string {
  interface Node {
    files: Map<string, { mode: string; oid: string }>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of files) {
    const parts = path.split('/').filter((p) => p !== '');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i]!;
      let child = node.dirs.get(part);
      if (!child) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(part, child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1]!, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    store.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/** Flatten a tree (recursively) into path -> {mode, oid}. */
function flattenTree(objects: Map<string, GitObject>, treeOid: string, prefix = ''): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const tree = objects.get(treeOid);
  if (!tree || tree.type !== 'tree') return out;
  for (const entry of parseTree(tree.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') {
      for (const [p, v] of flattenTree(objects, entry.oid, path)) out.set(p, v);
    } else {
      out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  }
  return out;
}

/** Walk the commit graph from `tips` (depth-limited when `maxDepth` is set: a commit at depth d
 *  has d ancestors above it; depth 1 means the tips only). Returns the set of commit oids
 *  reached and the set of boundary commits (at exactly maxDepth, when limited). Commits in
 *  `stopAt` are included but their parents are not walked: a shallow boundary the client
 *  already holds, whose history it does not have. */
function walkCommits(
  objects: Map<string, GitObject>,
  tips: string[],
  maxDepth?: number,
  stopAt?: Set<string>,
): { commits: Set<string>; boundary: Set<string> } {
  const commits = new Set<string>();
  const boundary = new Set<string>();
  const queue: Array<{ oid: string; depth: number }> = tips
    .filter((oid) => objects.get(oid)?.type === 'commit')
    .map((oid) => ({ oid, depth: 1 }));
  const seen = new Set<string>();
  while (queue.length) {
    const { oid, depth } = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    commits.add(oid);
    if (maxDepth !== undefined && depth >= maxDepth) {
      boundary.add(oid);
      continue;
    }
    if (stopAt?.has(oid)) {
      boundary.add(oid);
      continue;
    }
    const commit = parseCommit(objects.get(oid)!.data);
    for (const parent of commit.parents) {
      if (!seen.has(parent) && objects.get(parent)?.type === 'commit') queue.push({ oid: parent, depth: depth + 1 });
    }
  }
  return { commits, boundary };
}

/** All objects reachable from `tips` (commits + their trees/blobs, tag targets), optionally
 *  depth-limited the same way as walkCommits, and optionally minus objects reachable from
 *  `excludeTips` (already-held history). */
function reachableObjects(
  objects: Map<string, GitObject>,
  tips: string[],
  opts: { maxDepth?: number; stopAt?: Set<string>; excludeTips?: string[]; excludeStopAt?: Set<string> } = {},
): Set<string> {
  // `stopAt` limits THIS walk only (a shallow boundary whose parents are not walked).
  // `excludeStopAt` applies only to the held-history walk below. The two are kept apart
  // on purpose: a deepen fetch's wants walk must pass straight through the old shallow
  // boundary (the depth limit is what cuts it off), while the held walk must stop there
  // (the client holds that commit but not its parents).
  const { commits, boundary } = walkCommits(objects, tips, opts.maxDepth, opts.stopAt);
  const out = new Set<string>();
  const visitTree = (treeOid: string, seenTrees: Set<string>): void => {
    if (seenTrees.has(treeOid)) return;
    seenTrees.add(treeOid);
    const tree = objects.get(treeOid);
    if (!tree || tree.type !== 'tree') return;
    out.add(treeOid);
    for (const entry of parseTree(tree.data)) {
      if (entry.mode === '40000') visitTree(entry.oid, seenTrees);
      else out.add(entry.oid);
    }
  };
  const seenTrees = new Set<string>();
  for (const oid of commits) {
    out.add(oid);
    const commit = parseCommit(objects.get(oid)!.data);
    visitTree(commit.tree, seenTrees);
  }
  // Tag objects named directly as tips resolve to their target.
  for (const tip of tips) {
    const obj = objects.get(tip);
    if (obj?.type === 'tag') {
      out.add(tip);
      const target = parseTag(obj.data).object;
      const targetObj = objects.get(target);
      if (targetObj?.type === 'commit') {
        const sub = reachableObjects(objects, [target], { maxDepth: opts.maxDepth, stopAt: opts.stopAt });
        for (const oid of sub) out.add(oid);
      } else if (targetObj) {
        out.add(target);
      }
    }
  }
  if (opts.excludeTips && opts.excludeTips.length) {
    // Objects the client already holds: the full history of each have — except that a
    // have named in the request's shallow boundaries is held shallowly (the commit and
    // its tree, but not its parents), so the walk stops there.
    const held = reachableObjects(objects, opts.excludeTips, { stopAt: opts.excludeStopAt });
    for (const oid of held) out.delete(oid);
  }
  return out;
}

/** Peel a ref target to its commit (following annotated tags). */
function peelToCommit(objects: Map<string, GitObject>, oid: string): string | null {
  let current = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = objects.get(current);
    if (!obj) return null;
    if (obj.type === 'commit') return current;
    if (obj.type === 'tag') {
      current = parseTag(obj.data).object;
      continue;
    }
    return null;
  }
  return null;
}

/** Is `descendant` reachable from `ancestor` (same commit), i.e. a fast-forward? */
function isDescendant(objects: Map<string, GitObject>, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const { commits } = walkCommits(objects, [descendant]);
  return commits.has(ancestor);
}

/** The merge-base of two commits (nearest common ancestor by generation). */
function mergeBase(objects: Map<string, GitObject>, a: string, b: string): string | null {
  const aAnc = walkCommits(objects, [a]).commits;
  const queue: string[] = [b];
  const seen = new Set<string>();
  while (queue.length) {
    const oid = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (aAnc.has(oid)) return oid;
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queue.push(parent);
  }
  return null;
}

// -------------------------------------------------------------------------------------------
// Pack files (v2, no deltas on the way out; deltas resolved on the way in)
// -------------------------------------------------------------------------------------------

const PACK_TYPES: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_IDS: Record<ObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

function writePack(objects: Array<{ type: ObjectType; data: Buffer }>): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK'), Buffer.alloc(4), Buffer.alloc(4)];
  parts[1].writeUInt32BE(2, 0);
  parts[2].writeUInt32BE(objects.length, 0);
  for (const obj of objects) {
    const typeId = PACK_TYPE_IDS[obj.type];
    const size = obj.data.length;
    // Type + size varint header, little-endian 7-bit groups, MSB continuation.
    let header = (typeId << 4) | (size & 0x0f);
    let rest = size >> 4;
    const bytes: number[] = [header];
    while (rest > 0) {
      bytes[0] |= 0x80;
      bytes.push(rest & 0x7f);
      rest >>= 7;
    }
    // The continuation bit lives on every byte but the last; fix the chain.
    for (let i = 0; i < bytes.length - 1; i += 1) bytes[i] |= 0x80;
    bytes[bytes.length - 1] &= 0x7f;
    parts.push(Buffer.from(bytes));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

/** Parse a pack into objects (oid -> {type, data}), resolving OFS/REF deltas. */
function readPack(pack: Buffer): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  let off = 12;
  const byOffset = new Map<number, string>();
  interface DeltaEntry {
    oid: string;
    base: string | number;
    data: Buffer;
    offset: number;
  }
  const deltas: DeltaEntry[] = [];
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    let byte = pack[off++];
    const typeId = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[off++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeId === 6) {
      // OFS_DELTA: offset encoded in the following bytes.
      byte = pack[off++];
      let baseOffset = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[off++];
        baseOffset = ((baseOffset + 1) << 7) | (byte & 0x7f);
      }
      const basePos = entryOffset - baseOffset;
      const { data: raw, consumed } = inflateAt(pack, off);
      off += consumed;
      const deltaOid = `ofs:${entryOffset}`;
      deltas.push({ oid: deltaOid, base: basePos, data: raw, offset: entryOffset });
      void size;
    } else if (typeId === 7) {
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      const { data: raw, consumed } = inflateAt(pack, off);
      off += consumed;
      const deltaOid = `ref:${entryOffset}`;
      deltas.push({ oid: deltaOid, base: baseOid, data: raw, offset: entryOffset });
      void size;
    } else {
      const type = PACK_TYPES[typeId];
      if (!type) throw new Error(`unknown pack object type ${typeId}`);
      const { data: raw, consumed } = inflateAt(pack, off);
      off += consumed;
      if (raw.length !== size) throw new Error('pack object size mismatch');
      const oid = hashObject(type, raw);
      out.set(oid, { type, data: raw });
      byOffset.set(entryOffset, oid);
    }
  }
  // Resolve deltas (base objects may themselves be deltas; resolve in offset order).
  const resolveDelta = (entry: DeltaEntry): { type: ObjectType; data: Buffer } => {
    let baseOid: string;
    if (typeof entry.base === 'number') {
      const found = byOffset.get(entry.base);
      if (!found) throw new Error('delta base offset not found');
      baseOid = found;
    } else {
      baseOid = entry.base;
    }
    let base = out.get(baseOid);
    if (!base) {
      const baseDelta = deltas.find((d) => d.oid === `ofs:${entry.base}` || d.oid === `ref:${entry.base}`);
      if (!baseDelta) throw new Error('delta base object not found');
      const resolved = resolveDelta(baseDelta);
      base = resolved;
      out.set(baseOid, resolved);
    }
    const data = applyDelta(base.data, entry.data);
    return { type: base.type, data };
  };
  for (const entry of deltas) {
    const resolved = resolveDelta(entry);
    const oid = hashObject(resolved.type, resolved.data);
    out.set(oid, resolved);
    byOffset.set(entry.offset, oid);
  }
  return out;
}

/** How many bytes the deflate stream starting at `off` consumes (zlib sync flush probe). */
function deflatedLength(pack: Buffer, off: number): number {
  // Inflate with a window and measure by re-deflating is unreliable; instead use zlib's
  // stream API indirectly: try increasing slices until inflate succeeds exactly.
  // The pack layout guarantees the stream ends at a byte boundary; binary-search the end.
  let lo = off;
  let hi = pack.length;
  // Fast path: most streams end well before the pack end; grow exponentially first.
  let probe = Math.min(pack.length, off + 64);
  while (probe <= pack.length) {
    try {
      inflateSync(pack.subarray(off, probe));
      hi = probe;
      break;
    } catch {
      if (probe === pack.length) throw new Error('unterminated deflate stream in pack');
      probe = Math.min(pack.length, probe * 2);
    }
  }
  while (lo + 1 < hi) {
    const mid = Math.floor((lo + hi) / 2);
    try {
      inflateSync(pack.subarray(off, mid));
      hi = mid;
    } catch {
      lo = mid;
    }
  }
  return hi - off;
}

/**
 * Inflate the single deflate stream starting at `off` and report both the raw bytes and
 * how many pack bytes the stream consumed — in ONE inflate. Node's `inflateSync(...,
 * {info: true})` returns the zlib engine, whose `bytesWritten` is exactly the number of
 * input bytes the engine consumed before reaching the stream end (verified empirically:
 * exact match for compressible, random, tiny and empty payloads, with and without
 * trailing bytes — and the kit's own git-client uses the identical trick in its
 * `inflateAt`). Any inconsistency falls back to the binary search.
 */
function inflateAt(pack: Buffer, off: number): { data: Buffer; consumed: number } {
  try {
    const r = inflateSync(pack.subarray(off), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten?: number };
    };
    const consumed = r.engine?.bytesWritten;
    if (typeof consumed === 'number' && consumed > 0 && off + consumed <= pack.length) {
      return { data: r.buffer, consumed };
    }
  } catch {
    // fall through to the probe-based path
  }
  const consumed = deflatedLength(pack, off);
  return { data: inflateSync(pack.subarray(off, off + consumed)), consumed };
}

/** Apply a git delta (base + delta -> result). */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off++];
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const baseSize = readVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const resultSize = readVarint();
  const chunks: Buffer[] = [];
  let produced = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) cpOff |= delta[off++] << (8 * i);
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) cpSize |= delta[off++] << (8 * i);
      if (cpSize === 0) cpSize = 0x10000;
      chunks.push(base.subarray(cpOff, cpOff + cpSize));
      produced += cpSize;
    } else if (op !== 0) {
      chunks.push(delta.subarray(off, off + op));
      off += op;
      produced += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const result = Buffer.concat(chunks);
  if (result.length !== resultSize || produced !== resultSize) throw new Error('delta result size mismatch');
  return result;
}

// -------------------------------------------------------------------------------------------
// Store: repositories, issues, pull requests, labels, comments (all in-memory)
// -------------------------------------------------------------------------------------------

export interface IssueComment {
  id: number;
  body: string;
  user: string;
  createdAt: string;
  seq: number;
}

export interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: IssueComment[];
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
}

export interface PullRequest {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string; // branch name
  base: string; // branch name
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
}

export interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  createdSeq: number;
  createdAt: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  labels: Map<string, { name: string; color: string }>;
  issues: Issue[];
  pulls: PullRequest[];
  nextNumber: number; // shared issue/PR counter (GitHub semantics)
  nextCommentId: number;
}

const repos = new Map<string, Repo>(); // key: `${owner}/${name}`
let nextRepoId = 1;
let storeSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(owner: string, name: string, isPrivate: boolean, description: string): Repo {
  storeSeq += 1;
  const repo: Repo = {
    id: nextRepoId++,
    name,
    owner,
    private: isPrivate,
    description,
    defaultBranch: DEFAULT_BRANCH,
    createdSeq: storeSeq,
    createdAt: isoOf(nextTimestamp()),
    refs: new Map(),
    objects: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    nextNumber: 1,
    nextCommentId: 1,
  };
  for (const label of DEFAULT_LABELS) repo.labels.set(label, { name: label, color: 'ededed' });
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | null {
  return repos.get(repoKey(owner, name)) ?? null;
}

function globalId(kind: string, repoId: number, n: number, extra = ''): string {
  return b64encode(`${kind}:${repoId}:${n}${extra}`);
}

function parseGlobalId(id: string): { kind: string; repoId: number; n: number; extra: string } | null {
  try {
    const text = b64decode(id).toString('utf8');
    const m = /^([A-Za-z]+):(\d+):(\d+)(?::(.*))?$/.exec(text);
    if (!m) return null;
    return { kind: m[1]!, repoId: Number(m[2]), n: Number(m[3]), extra: m[4] ?? '' };
  } catch {
    return null;
  }
}

function repoById(id: number): Repo | null {
  for (const repo of repos.values()) if (repo.id === id) return repo;
  return null;
}

/** Resolve a ref name (branch, full ref, or sha) to a commit oid, or null. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  if (repo.refs.has(ref)) return repo.refs.get(ref)!;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`)!;
  if (ref === 'HEAD') return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  return null;
}

/** The tree oid at a commit, or null. */
function treeOfCommit(repo: Repo, commitOid: string): string | null {
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data).tree;
}

/** Create a commit on `branch` that replaces/adds `files` (path -> content Buffer) in the
 *  branch's tree. Returns the new commit oid. Creates the branch from the default tip (or
 *  from nothing when the repo is unborn) when it does not exist. */
function commitFiles(
  repo: Repo,
  branch: string,
  files: Array<{ path: string; content: Buffer | null }>, // null content = delete
  message: string,
): string {
  const refName = `refs/heads/${branch}`;
  const currentTip = repo.refs.get(refName) ?? repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const baseFiles = new Map<string, { mode: string; oid: string }>();
  if (currentTip) {
    const tree = treeOfCommit(repo, currentTip);
    if (tree) for (const [p, v] of flattenTree(repo.objects, tree)) baseFiles.set(p, v);
  }
  for (const file of files) {
    if (file.content === null) {
      baseFiles.delete(file.path);
    } else {
      const blobOid = hashObject('blob', file.content);
      repo.objects.set(blobOid, { type: 'blob', data: file.content });
      baseFiles.set(file.path, { mode: '100644', oid: blobOid });
    }
  }
  const treeOid = buildTreeFromFiles(baseFiles, repo.objects);
  const ts = nextTimestamp();
  const parents = currentTip && repo.refs.has(refName) ? [currentTip] : [];
  const commitData = buildCommit(treeOid, parents, message, ts);
  const commitOid = hashObject('commit', commitData);
  repo.objects.set(commitOid, { type: 'commit', data: commitData });
  repo.refs.set(refName, commitOid);
  return commitOid;
}

/** Diff two trees: path -> {status, oldOid?, newOid?}. */
function diffTrees(
  repo: Repo,
  baseTreeOid: string | null,
  headTreeOid: string | null,
): Array<{ path: string; status: 'added' | 'modified' | 'deleted'; oldOid: string | null; newOid: string | null }> {
  const base = baseTreeOid ? flattenTree(repo.objects, baseTreeOid) : new Map<string, { mode: string; oid: string }>();
  const head = headTreeOid ? flattenTree(repo.objects, headTreeOid) : new Map<string, { mode: string; oid: string }>();
  const out: Array<{ path: string; status: 'added' | 'modified' | 'deleted'; oldOid: string | null; newOid: string | null }> = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && !h) out.push({ path, status: 'deleted', oldOid: b.oid, newOid: null });
    else if (!b && h) out.push({ path, status: 'added', oldOid: null, newOid: h.oid });
    else if (b && h && b.oid !== h.oid) out.push({ path, status: 'modified', oldOid: b.oid, newOid: h.oid });
  }
  return out;
}

/** Line counts for a file change (multiset diff of lines). */
function lineCounts(repo: Repo, oldOid: string | null, newOid: string | null): { additions: number; deletions: number } {
  const oldLines = oldOid ? (repo.objects.get(oldOid)?.data.toString('utf8') ?? '').split('\n') : [];
  const newLines = newOid ? (repo.objects.get(newOid)?.data.toString('utf8') ?? '').split('\n') : [];
  const count = (lines: string[]): Map<string, number> => {
    const m = new Map<string, number>();
    for (const line of lines) m.set(line, (m.get(line) ?? 0) + 1);
    return m;
  };
  const a = count(oldLines);
  const b = count(newLines);
  let additions = 0;
  let deletions = 0;
  for (const [line, n] of b) additions += Math.max(0, n - (a.get(line) ?? 0));
  for (const [line, n] of a) deletions += Math.max(0, n - (b.get(line) ?? 0));
  return { additions, deletions };
}

/** Would merging `headTip` into `baseTip` conflict? (same path changed both sides to
 *  different blobs since the merge-base). */
function mergeConflict(repo: Repo, baseTip: string, headTip: string): boolean {
  const base = mergeBase(repo.objects, baseTip, headTip);
  if (!base) return false;
  const baseTree = treeOfCommit(repo, base);
  const baseTipTree = treeOfCommit(repo, baseTip);
  const headTipTree = treeOfCommit(repo, headTip);
  const baseSide = diffTrees(repo, baseTree, baseTipTree);
  const headSide = diffTrees(repo, baseTree, headTipTree);
  const headByPath = new Map(headSide.map((d) => [d.path, d]));
  for (const d of baseSide) {
    const h = headByPath.get(d.path);
    if (h && d.newOid !== h.newOid) return true;
  }
  return false;
}

function mergeableState(repo: Repo, pull: PullRequest): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  const baseTip = repo.refs.get(`refs/heads/${pull.base}`);
  const headTip = repo.refs.get(`refs/heads/${pull.head}`);
  if (!baseTip || !headTip) return 'UNKNOWN';
  return mergeConflict(repo, baseTip, headTip) ? 'CONFLICTING' : 'MERGEABLE';
}

/** Squash-merge a pull request onto its base branch. Returns the merge commit oid, or null
 *  when the PR is conflicted. */
function squashMerge(repo: Repo, pull: PullRequest): string | null {
  const baseTip = repo.refs.get(`refs/heads/${pull.base}`);
  const headTip = repo.refs.get(`refs/heads/${pull.head}`);
  if (!baseTip || !headTip) return null;
  if (mergeConflict(repo, baseTip, headTip)) return null;
  const base = mergeBase(repo.objects, baseTip, headTip);
  const baseTree = base ? treeOfCommit(repo, base) : null;
  const headTree = treeOfCommit(repo, headTip);
  const baseTipTree = treeOfCommit(repo, baseTip);
  // Result tree: base tip's tree with the head side's changes applied.
  const files = baseTipTree ? flattenTree(repo.objects, baseTipTree) : new Map<string, { mode: string; oid: string }>();
  for (const d of diffTrees(repo, baseTree, headTree)) {
    if (d.status === 'deleted') files.delete(d.path);
    else if (d.newOid) files.set(d.path, { mode: '100644', oid: d.newOid });
  }
  const treeOid = buildTreeFromFiles(files, repo.objects);
  const ts = nextTimestamp();
  const commitData = buildCommit(treeOid, [baseTip], `Merge pull request #${pull.number} from ${pull.head}\n\n${pull.title}\n`, ts);
  const mergeOid = hashObject('commit', commitData);
  repo.objects.set(mergeOid, { type: 'commit', data: commitData });
  repo.refs.set(`refs/heads/${pull.base}`, mergeOid);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoOf(ts);
  pull.mergeCommitSha = mergeOid;
  pull.updatedAt = isoOf(ts);
  return mergeOid;
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing
// -------------------------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), 'x-github-request-id': nextRequestId(), ...extraHeaders });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': nextRequestId(), ...extraHeaders });
  res.end(body);
}

function sendNoContent(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'x-github-request-id': nextRequestId() });
  res.end();
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false; error: string } {
  if (buf.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) as unknown };
  } catch {
    return { ok: false, error: 'Problems parsing JSON' };
  }
}

function bearerToken(req: IncomingMessage): string | null {
  const auth = req.headers.authorization ?? '';
  const m = /^Bearer\s+(.+)$/.exec(auth);
  return m ? m[1]! : null;
}

function expectedToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

/** The token the trial hands the entry; when unset locally, any non-empty token is accepted
 *  for practice runs (the runner always passes one). */
function tokenIsValid(token: string | null): boolean {
  const expected = expectedToken();
  if (expected !== '') return token === expected;
  return token !== null && token !== '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function notFound(res: ServerResponse, message = 'Not Found'): void {
  sendJson(res, 404, { message });
}

function unauthorized(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Requires authentication' });
}

// -------------------------------------------------------------------------------------------
// Git smart HTTP
// -------------------------------------------------------------------------------------------

const V2_CAPS = ['agent=' + AGENT, 'ls-refs=unborn', 'fetch=shallow', 'object-format=sha1'];
const RECEIVE_CAPS = ['report-status', 'side-band-64k', 'ofs-delta', 'delete-refs', 'agent=' + AGENT];

function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

/** The v0 ref advertisement lines for a repo (HEAD first, then sorted refs, peeled tags). */
function v0RefLines(repo: Repo): string[] {
  const lines: string[] = [];
  const headTarget = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (headTarget) lines.push(`${headTarget} HEAD`);
  else lines.push(`${ZERO_OID} HEAD`);
  for (const name of sortedRefNames(repo)) {
    const oid = repo.refs.get(name)!;
    lines.push(`${oid} ${name}`);
    const obj = repo.objects.get(oid);
    if (obj?.type === 'tag') {
      const peeled = peelToCommit(repo.objects, oid);
      if (peeled) lines.push(`${peeled} ${name}^{}`);
    }
  }
  return lines;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const lines = v0RefLines(repo);
  const caps = service === 'git-receive-pack' ? RECEIVE_CAPS.join(' ') : `symref=HEAD:refs/heads/${repo.defaultBranch} agent=${AGENT}`;
  const parts: Buffer[] = [pktText(`# service=${service}\n`), PKT_FLUSH];
  if (lines.length === 0) {
    parts.push(pktText(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    lines.forEach((line, i) => {
      parts.push(pktText(i === 0 ? `${line}\0${caps}\n` : `${line}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(service: 'git-upload-pack'): Buffer {
  const parts: Buffer[] = [pktText(`# service=${service}\n`), PKT_FLUSH, pktText('version 2\n')];
  for (const cap of V2_CAPS) parts.push(pktText(`${cap}\n`));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface LsRefLine {
  oid: string;
  name: string;
  symrefTarget?: string;
  peeled?: string;
  unborn?: boolean;
}

function lsRefsLines(repo: Repo, opts: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): LsRefLine[] {
  const out: LsRefLine[] = [];
  const keep = (name: string): boolean => opts.prefixes.length === 0 || opts.prefixes.some((p) => name.startsWith(p));
  if (opts.symrefs && keep('HEAD')) {
    const headTarget = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    if (headTarget) out.push({ oid: headTarget, name: 'HEAD', symrefTarget: `refs/heads/${repo.defaultBranch}` });
    else if (opts.unborn) out.push({ oid: ZERO_OID, name: 'HEAD', symrefTarget: `refs/heads/${repo.defaultBranch}`, unborn: true });
  }
  for (const name of sortedRefNames(repo)) {
    if (!keep(name)) continue;
    const oid = repo.refs.get(name)!;
    const line: LsRefLine = { oid, name };
    if (opts.peel) {
      const obj = repo.objects.get(oid);
      if (obj?.type === 'tag') {
        const peeled = peelToCommit(repo.objects, oid);
        if (peeled) line.peeled = peeled;
      }
    }
    out.push(line);
  }
  return out;
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, service: string): void {
  if (!tokenIsValid(bearerToken(req))) {
    unauthorized(res);
    return;
  }
  const repo = findRepo(owner, repoName);
  if (!repo) {
    notFound(res);
    return;
  }
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    notFound(res);
    return;
  }
  const wantsV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  const body = wantsV2 ? v2Advertisement(service) : v0Advertisement(repo, service);
  sendRaw(res, 200, `application/x-${service}-advertisement`, body);
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  filter: string | null;
}

function parseFetchRequest(packets: Pkt[]): FetchRequest {
  const req: FetchRequest = { wants: [], haves: [], shallow: [], depth: null, filter: null };
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) req.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) req.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) req.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) req.depth = Number(line.slice(7).trim());
    else if (line.startsWith('filter ')) req.filter = line.slice(7).trim();
  }
  return req;
}

function handleUploadPack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, body: Buffer): void {
  if (!tokenIsValid(bearerToken(req))) {
    unauthorized(res);
    return;
  }
  const repo = findRepo(owner, repoName);
  if (!repo) {
    notFound(res);
    return;
  }
  let packets: Pkt[];
  try {
    packets = decodePktLines(body);
  } catch {
    sendJson(res, 400, { message: 'Invalid pkt-line stream' });
    return;
  }
  const first = packets.find((p) => p.kind === 'data')?.payload.toString('utf8').replace(/\n$/, '') ?? '';
  if (first.startsWith('command=ls-refs')) {
    handleLsRefs(repo, res, packets);
    return;
  }
  if (first.startsWith('command=fetch')) {
    handleFetch(repo, res, packets);
    return;
  }
  sendJson(res, 400, { message: 'Unknown git command' });
}

function handleLsRefs(repo: Repo, res: ServerResponse, packets: Pkt[]): void {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line === 'peel') peel = true;
    else if (line === 'symrefs') symrefs = true;
    else if (line === 'unborn') unborn = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
  }
  const lines = lsRefsLines(repo, { peel, symrefs, unborn, prefixes });
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line.unborn) {
      parts.push(pktText(`unborn ${line.name} symref-target:${line.symrefTarget ?? ''}\n`));
      continue;
    }
    let text = `${line.oid} ${line.name}`;
    if (line.symrefTarget) text += ` symref-target:${line.symrefTarget}`;
    if (line.peeled) text += ` peeled:${line.peeled}`;
    parts.push(pktText(`${text}\n`));
  }
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleFetch(repo: Repo, res: ServerResponse, packets: Pkt[]): void {
  const request = parseFetchRequest(packets);
  const wants = [...new Set(request.wants)].filter((oid) => repo.objects.has(oid));
  // Compute the object set.
  let objectIds: Set<string>;
  let shallowOut: string[] = [];
  let unshallowOut: string[] = [];
  if (request.depth !== null) {
    const { boundary } = walkCommits(repo.objects, wants, request.depth);
    objectIds = reachableObjects(repo.objects, wants, {
      maxDepth: request.depth,
      excludeTips: request.haves,
      excludeStopAt: new Set(request.shallow),
    });
    shallowOut = [...boundary].sort();
    // Old shallow boundaries now within the new depth are unshallow.
    const { commits: within } = walkCommits(repo.objects, wants, request.depth);
    for (const old of request.shallow) {
      if (within.has(old) && !boundary.has(old)) unshallowOut.push(old);
    }
    unshallowOut.sort();
  } else {
    objectIds = reachableObjects(repo.objects, wants, {
      excludeTips: request.haves,
      excludeStopAt: new Set(request.shallow),
    });
    shallowOut = [...request.shallow].sort();
  }
  const objects = [...objectIds]
    .map((oid) => ({ oid, obj: repo.objects.get(oid)! }))
    .filter((entry) => entry.obj !== undefined)
    .sort((a, b) => (a.oid < b.oid ? -1 : 1));
  const pack = writePack(objects.map((entry) => entry.obj));
  const parts: Buffer[] = [];
  parts.push(pktText('acknowledgments\n'));
  parts.push(pktText('NAK\n'));
  parts.push(PKT_DELIM);
  if (shallowOut.length || unshallowOut.length) {
    parts.push(pktText('shallow-info\n'));
    for (const oid of shallowOut) parts.push(pktText(`shallow ${oid}\n`));
    for (const oid of unshallowOut) parts.push(pktText(`unshallow ${oid}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktText('packfile\n'));
  for (const packet of sidebandPackets(1, pack)) parts.push(packet);
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, body: Buffer): void {
  if (!tokenIsValid(bearerToken(req))) {
    unauthorized(res);
    return;
  }
  const repo = findRepo(owner, repoName);
  if (!repo) {
    notFound(res);
    return;
  }
  // The command list is pkt-lines terminated by a flush; the pack follows raw.
  let flushEnd = -1;
  let off = 0;
  while (off + 4 <= body.length) {
    const len = parseInt(body.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len)) break;
    if (len === 0) {
      flushEnd = off + 4;
      break;
    }
    if (len < 4 || off + len > body.length) break;
    off += len;
  }
  if (flushEnd < 0) {
    sendPushReport(res, false, 'unpack error', []);
    return;
  }
  let commands: PushCommand[] = [];
  try {
    const packets = decodePktLines(body.subarray(0, flushEnd));
    for (const packet of packets) {
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8').replace(/\n$/, '');
      const nul = text.indexOf('\0');
      const head = nul >= 0 ? text.slice(0, nul) : text;
      const parts = head.split(' ');
      if (parts.length < 3) continue;
      commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts[2]! });
    }
  } catch {
    sendPushReport(res, false, 'unpack error', []);
    return;
  }
  const packBytes = body.subarray(flushEnd);
  const hasUpdates = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (hasUpdates) {
    if (packBytes.length === 0) {
      unpackOk = false;
      unpackDetail = 'unpack error';
    } else {
      try {
        const objects = readPack(packBytes);
        for (const [oid, obj] of objects) repo.objects.set(oid, obj);
      } catch {
        unpackOk = false;
        unpackDetail = 'unpack error';
      }
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  for (const cmd of commands) {
    if (!unpackOk) {
      results.push({ ref: cmd.ref, ok: false, reason: 'unpack error' });
      continue;
    }
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // Delete.
      if (current === undefined) {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      } else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'old value mismatch' });
      } else {
        repo.refs.delete(cmd.ref);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
      continue;
    }
    if (!repo.objects.has(cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
      continue;
    }
    if (cmd.oldOid === ZERO_OID) {
      if (current !== undefined) {
        results.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
      continue;
    }
    if (current === undefined) {
      results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      continue;
    }
    if (current !== cmd.oldOid) {
      results.push({ ref: cmd.ref, ok: false, reason: 'old value mismatch' });
      continue;
    }
    if (!isDescendant(repo.objects, cmd.oldOid, cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    repo.refs.set(cmd.ref, cmd.newOid);
    results.push({ ref: cmd.ref, ok: true, reason: '' });
  }
  sendPushReport(res, unpackOk, unpackDetail, results);
}

function sendPushReport(
  res: ServerResponse,
  unpackOk: boolean,
  unpackDetail: string,
  results: Array<{ ref: string; ok: boolean; reason: string }>,
): void {
  const lines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
  for (const r of results) {
    lines.push(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`);
  }
  const report = Buffer.concat(lines.map((l) => pktText(l)));
  const parts: Buffer[] = [...sidebandPackets(1, report), ...sidebandPackets(2, Buffer.from('unpacking objects\n', 'utf8')), PKT_FLUSH];
  sendRaw(res, 200, 'application/x-git-receive-pack-result', Buffer.concat(parts));
}

// -------------------------------------------------------------------------------------------
// REST v3 (/api/v3)
// -------------------------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: globalId('Repository', repo.id, 0),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER.id, type: 'User' },
    private: repo.private,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: repo.createdAt,
    updated_at: repo.createdAt,
    pushed_at: repo.createdAt,
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.number,
    node_id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullJson(repo: Repo, pull: PullRequest): Record<string, unknown> {
  const headSha = repo.refs.get(`refs/heads/${pull.head}`) ?? pull.headSha;
  const baseSha = repo.refs.get(`refs/heads/${pull.base}`) ?? pull.baseSha;
  return {
    id: pull.number,
    node_id: globalId('PullRequest', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    head: { label: `${repo.owner}:${pull.head}`, ref: pull.head, sha: headSha },
    base: { label: `${repo.owner}:${pull.base}`, ref: pull.base, sha: baseSha },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: mergeableState(repo, pull),
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function commentJson(repo: Repo, issue: Issue, comment: IssueComment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('IssueComment', repo.id, issue.number, `:${comment.id}`),
    body: comment.body,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
  };
}

function branchJson(repo: Repo, name: string): Record<string, unknown> {
  const sha = repo.refs.get(`refs/heads/${name}`) ?? ZERO_OID;
  return {
    name,
    commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` },
    protected: false,
  };
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const obj = repo.objects.get(oid);
  const info = obj && obj.type === 'commit' ? parseCommit(obj.data) : null;
  const authorLine = info?.author ?? '';
  const committerLine = info?.committer ?? '';
  const parseIdentity = (line: string): { name: string; email: string; date: string } => {
    const m = /^(.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(line);
    if (!m) return { name: VIEWER.name, email: VIEWER.email, date: isoOf(EPOCH_SEC) };
    return { name: m[1]!, email: m[2]!, date: isoOf(Number(m[3])) };
  };
  const author = parseIdentity(authorLine);
  const committer = parseIdentity(committerLine);
  return {
    sha: oid,
    node_id: globalId('Commit', repo.id, 0, `:${oid.slice(0, 12)}`),
    commit: {
      // GitHub's API presents the message without the trailing newline the raw
      // commit object carries.
      message: (info?.message ?? '').replace(/\n$/, ''),
      author,
      committer,
      tree: { sha: info?.tree ?? ZERO_OID },
    },
    author: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    committer: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    parents: (info?.parents ?? []).map((p) => ({ sha: p })),
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
  };
}

function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; totalPages: number; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  const pageNum = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const start = (pageNum - 1) * perPage;
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  return { page: items.slice(start, start + perPage), totalPages, pageNum, perPage };
}

function linkHeader(req: IncomingMessage, path: string, query: URLSearchParams, pageNum: number, totalPages: number, perPage: number): string {
  const host = req.headers.host ?? '127.0.0.1';
  const base = `http://${host}${path}`;
  const q = new URLSearchParams(query);
  q.set('per_page', String(perPage));
  const links: string[] = [];
  if (pageNum < totalPages) {
    q.set('page', String(pageNum + 1));
    links.push(`<${base}?${q.toString()}>; rel="next"`);
  }
  if (totalPages > 1) {
    q.set('page', String(totalPages));
    links.push(`<${base}?${q.toString()}>; rel="last"`);
  }
  if (pageNum > 1) {
    q.set('page', String(1));
    links.push(`<${base}?${q.toString()}>; rel="first"`);
    q.set('page', String(pageNum - 1));
    links.push(`<${base}?${q.toString()}>; rel="prev"`);
  }
  return links.join(', ');
}

/** The repo a REST route names, or null when the owner is foreign or the repo is absent. */
function restRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER.login) return null;
  return findRepo(owner, name);
}

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, body: Buffer): Promise<void> {
  const method = req.method ?? 'GET';
  const query = queryOf(req);
  if (!tokenIsValid(bearerToken(req))) {
    unauthorized(res);
    return;
  }
  const api = path.replace(/^\/api\/v3\/?/, '');
  const segments = api.split('/').filter((s) => s !== '');

  // GET /api/v3/ and /api/v3/meta
  if (method === 'GET' && segments.length === 0) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (method === 'GET' && segments.length === 1 && segments[0] === 'meta') {
    sendJson(res, 200, { installed_version: INSTALLED_VERSION });
    return;
  }
  if (method === 'GET' && segments.length === 1 && segments[0] === 'user') {
    sendJson(res, 200, { login: VIEWER.login, id: VIEWER.id, node_id: globalId('User', VIEWER.id, 0), name: VIEWER.name, email: VIEWER.email, type: 'User' });
    return;
  }

  // POST /user/repos ; GET /user/repos
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const name = typeof input.name === 'string' ? input.name : '';
      if (!name) {
        sendJson(res, 422, { message: 'Validation Failed: name is required' });
        return;
      }
      if (findRepo(VIEWER.login, name)) {
        sendJson(res, 422, { message: 'Repository creation failed: name already exists on this account' });
        return;
      }
      const repo = createRepoRecord(VIEWER.login, name, input.private === true, typeof input.description === 'string' ? input.description : '');
      sendJson(res, 201, repoJson(repo));
      return;
    }
    if (method === 'GET') {
      const all = [...repos.values()].filter((r) => r.owner === VIEWER.login).sort((a, b) => a.createdSeq - b.createdSeq);
      const { page, totalPages, pageNum, perPage } = paginate(all, query);
      const link = linkHeader(req, '/api/v3/user/repos', query, pageNum, totalPages, perPage);
      sendJson(res, 200, page.map(repoJson), link ? { link } : {});
      return;
    }
    notFound(res);
    return;
  }

  // /repos/{owner}/{name}[...]
  if (segments.length >= 3 && segments[0] === 'repos') {
    const owner = decodeURIComponent(segments[1]!);
    const name = decodeURIComponent(segments[2]!);
    const repo = restRepo(owner, name);
    if (!repo) {
      notFound(res);
      return;
    }
    const rest = segments.slice(3);
    await handleRepoRest(req, res, repo, rest, body, query);
    return;
  }

  notFound(res);
}

async function handleRepoRest(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  rest: string[],
  body: Buffer,
  query: URLSearchParams,
): Promise<void> {
  const method = req.method ?? 'GET';
  const repoPath = `/api/v3/repos/${repo.owner}/${repo.name}`;

  // GET/PATCH/DELETE /repos/{o}/{r}
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      if (typeof input.description === 'string') repo.description = input.description;
      if (typeof input.private === 'boolean') repo.private = input.private;
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      sendNoContent(res, 204);
      return;
    }
    notFound(res);
    return;
  }

  // Branches
  if (rest[0] === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const names = [...repo.refs.keys()].filter((r) => r.startsWith('refs/heads/')).map((r) => r.slice('refs/heads/'.length)).sort();
      sendJson(res, 200, names.map((n) => branchJson(repo, n)));
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      const branch = decodeURIComponent(rest[1]!);
      if (!repo.refs.has(`refs/heads/${branch}`)) {
        notFound(res, 'Branch not found');
        return;
      }
      sendJson(res, 200, branchJson(repo, branch));
      return;
    }
    notFound(res);
    return;
  }

  // Commits
  if (rest[0] === 'commits' && method === 'GET') {
    if (rest.length === 2) {
      const oid = decodeURIComponent(rest[1]!);
      if (!repo.objects.has(oid) || repo.objects.get(oid)?.type !== 'commit') {
        notFound(res);
        return;
      }
      sendJson(res, 200, commitJson(repo, oid));
      return;
    }
    const shaParam = query.get('sha');
    const tip = shaParam ? resolveRef(repo, shaParam) : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    if (!tip) {
      sendJson(res, 200, []);
      return;
    }
    const { commits } = walkCommits(repo.objects, [tip]);
    const list = [...commits]
      .map((oid) => ({ oid, ts: commitTimestamp(repo, oid) }))
      .sort((a, b) => b.ts - a.ts || (a.oid < b.oid ? 1 : -1))
      .map((entry) => commitJson(repo, entry.oid));
    const { page } = paginate(list, query);
    sendJson(res, 200, page);
    return;
  }

  // Git refs (data API)
  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const ref = typeof input.ref === 'string' ? input.ref : '';
      const sha = typeof input.sha === 'string' ? input.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
        sendJson(res, 422, { message: 'Validation Failed: ref and sha are required' });
        return;
      }
      if (repo.refs.has(ref)) {
        sendJson(res, 422, { message: 'Reference already exists' });
        return;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: `${repoPath}/git/${repo.objects.get(sha)?.type ?? 'commit'}s/${sha}` } });
      return;
    }
    if (method === 'GET' && rest.length >= 3) {
      const ref = rest.slice(2).map((s) => decodeURIComponent(s)).join('/');
      const fullRef = ref.startsWith('refs/') ? ref : `refs/${ref}`;
      const oid = repo.refs.get(fullRef);
      if (!oid) {
        notFound(res, 'Reference does not exist');
        return;
      }
      sendJson(res, 200, { ref: fullRef, object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit' } });
      return;
    }
    notFound(res);
    return;
  }

  // Contents
  if (rest[0] === 'contents') {
    await handleContents(req, res, repo, rest.slice(1), body, query);
    return;
  }

  // Labels
  if (rest[0] === 'labels' && method === 'POST' && rest.length === 1) {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      sendJson(res, 400, { message: parsed.error });
      return;
    }
    const input = isRecord(parsed.value) ? parsed.value : {};
    const name = typeof input.name === 'string' ? input.name : '';
    const color = typeof input.color === 'string' ? input.color : 'ededed';
    if (!name) {
      sendJson(res, 422, { message: 'Validation Failed: name is required' });
      return;
    }
    repo.labels.set(name, { name, color });
    sendJson(res, 201, { name, color, description: '' });
    return;
  }

  // Issues
  if (rest[0] === 'issues') {
    await handleIssues(req, res, repo, rest.slice(1), body, query);
    return;
  }

  // Pulls
  if (rest[0] === 'pulls') {
    await handlePulls(req, res, repo, rest.slice(1), body, query);
    return;
  }

  notFound(res);
}

function commitTimestamp(repo: Repo, oid: string): number {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return 0;
  const committer = parseCommit(obj.data).committer;
  const m = / (\d+) [+-]\d{4}$/.exec(committer);
  return m ? Number(m[1]) : 0;
}

async function handleContents(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  pathParts: string[],
  body: Buffer,
  query: URLSearchParams,
): Promise<void> {
  const method = req.method ?? 'GET';
  const filePath = pathParts.map((s) => decodeURIComponent(s)).join('/');
  const refParam = query.get('ref');
  const branch = refParam ?? repo.defaultBranch;
  const tip = resolveRef(repo, branch);

  if (method === 'GET') {
    if (!tip) {
      notFound(res);
      return;
    }
    const treeOid = treeOfCommit(repo, tip);
    if (!treeOid) {
      notFound(res);
      return;
    }
    if (filePath === '') {
      // Root listing.
      const entries = parseTree(repo.objects.get(treeOid)!.data).map((entry) => contentEntry(repo, entry, entry.name));
      sendJson(res, 200, entries);
      return;
    }
    const files = flattenTree(repo.objects, treeOid);
    const file = files.get(filePath);
    if (file) {
      const blob = repo.objects.get(file.oid)!;
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        content: b64encode(blob.data),
        sha: file.oid,
        size: blob.data.length,
        name: filePath.split('/').pop(),
        path: filePath,
        url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
      });
      return;
    }
    // Directory?
    const prefix = `${filePath}/`;
    const children = new Map<string, TreeEntry>();
    const tree = repo.objects.get(treeOid)!;
    let current: Buffer | null = tree.data;
    let currentPrefix = '';
    // Walk down to the directory's tree.
    const parts = filePath.split('/');
    let ok = true;
    for (const part of parts) {
      const entries = parseTree(current!);
      const found = entries.find((e) => e.name === part);
      if (!found || found.mode !== '40000') {
        ok = false;
        break;
      }
      const sub = repo.objects.get(found.oid);
      if (!sub) {
        ok = false;
        break;
      }
      current = sub.data;
      currentPrefix = currentPrefix === '' ? part : `${currentPrefix}/${part}`;
    }
    if (!ok || !current) {
      notFound(res);
      return;
    }
    const entries = parseTree(current).map((entry) => contentEntry(repo, entry, `${currentPrefix}/${entry.name}`));
    sendJson(res, 200, entries);
    return;
  }

  if (method === 'PUT') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      sendJson(res, 400, { message: parsed.error });
      return;
    }
    const input = isRecord(parsed.value) ? parsed.value : {};
    const message = typeof input.message === 'string' ? input.message : 'Update file';
    const contentB64 = typeof input.content === 'string' ? input.content : '';
    const targetBranch = typeof input.branch === 'string' ? input.branch : repo.defaultBranch;
    const sha = typeof input.sha === 'string' ? input.sha : undefined;
    const content = b64decode(contentB64);
    const refName = `refs/heads/${targetBranch}`;
    const targetTip = repo.refs.get(refName);
    const files = targetTip ? flattenTree(repo.objects, treeOfCommit(repo, targetTip)!) : new Map<string, { mode: string; oid: string }>();
    const existing = files.get(filePath);
    if (existing) {
      if (!sha) {
        sendJson(res, 409, { message: 'sha is required to update a file' });
        return;
      }
      if (sha.toLowerCase() !== existing.oid.toLowerCase()) {
        sendJson(res, 409, { message: 'sha does not match the current blob' });
        return;
      }
    }
    const commitOid = commitFiles(repo, targetBranch, [{ path: filePath, content }], message);
    const blobOid = hashObject('blob', content);
    const status = existing ? 200 : 201;
    sendJson(res, status, {
      content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: content.length, encoding: 'base64', url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}` },
      commit: { sha: commitOid, message, author: { name: VIEWER.name, email: VIEWER.email }, committer: { name: VIEWER.name, email: VIEWER.email } },
    });
    return;
  }

  if (method === 'DELETE') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      sendJson(res, 400, { message: parsed.error });
      return;
    }
    const input = isRecord(parsed.value) ? parsed.value : {};
    const message = typeof input.message === 'string' ? input.message : 'Delete file';
    const sha = typeof input.sha === 'string' ? input.sha : undefined;
    const refName = `refs/heads/${repo.defaultBranch}`;
    const targetTip = repo.refs.get(refName);
    if (!targetTip) {
      notFound(res);
      return;
    }
    const files = flattenTree(repo.objects, treeOfCommit(repo, targetTip)!);
    const existing = files.get(filePath);
    if (!existing) {
      notFound(res);
      return;
    }
    if (sha && sha.toLowerCase() !== existing.oid.toLowerCase()) {
      sendJson(res, 409, { message: 'sha does not match the current blob' });
      return;
    }
    const commitOid = commitFiles(repo, repo.defaultBranch, [{ path: filePath, content: null }], message);
    sendJson(res, 200, { commit: { sha: commitOid, message } });
    return;
  }

  notFound(res);
}

function contentEntry(repo: Repo, entry: TreeEntry, path: string): Record<string, unknown> {
  const obj = repo.objects.get(entry.oid);
  const size = obj && obj.type === 'blob' ? obj.data.length : 0;
  return {
    type: entry.mode === '40000' ? 'dir' : 'file',
    name: entry.name,
    path,
    sha: entry.oid,
    size,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
  };
}

async function handleIssues(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  rest: string[],
  body: Buffer,
  query: URLSearchParams,
): Promise<void> {
  const method = req.method ?? 'GET';

  if (rest.length === 0) {
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const title = typeof input.title === 'string' ? input.title : '';
      const bodyText = typeof input.body === 'string' ? input.body : '';
      const labels = Array.isArray(input.labels) ? input.labels.filter((l): l is string => typeof l === 'string') : [];
      for (const label of labels) {
        if (!repo.labels.has(label)) {
          sendJson(res, 422, { message: `Validation Failed: label "${label}" does not exist` });
          return;
        }
      }
      const ts = nextTimestamp();
      const issue: Issue = {
        number: repo.nextNumber++,
        title,
        body: bodyText,
        state: 'open',
        labels,
        comments: [],
        createdSeq: storeSeq++,
        createdAt: isoOf(ts),
        updatedAt: isoOf(ts),
      };
      repo.issues.push(issue);
      sendJson(res, 201, issueJson(repo, issue));
      return;
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      const sort = query.get('sort') ?? 'created';
      const direction = query.get('direction') ?? 'desc';
      let list = [...repo.issues];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      if (sort === 'created') {
        list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      }
      const { page } = paginate(list, query);
      sendJson(res, 200, page.map((i) => issueJson(repo, i)));
      return;
    }
    notFound(res);
    return;
  }

  const number = Number(rest[0]);
  if (!Number.isInteger(number)) {
    notFound(res);
    return;
  }
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) {
    notFound(res);
    return;
  }

  if (rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, issueJson(repo, issue));
      return;
    }
    if (method === 'PATCH') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      if (typeof input.state === 'string' && (input.state === 'open' || input.state === 'closed')) issue.state = input.state;
      if (typeof input.title === 'string') issue.title = input.title;
      if (typeof input.body === 'string') issue.body = input.body;
      issue.updatedAt = isoOf(nextTimestamp());
      sendJson(res, 200, issueJson(repo, issue));
      return;
    }
    notFound(res);
    return;
  }

  if (rest.length === 2 && rest[1] === 'comments') {
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const text = typeof input.body === 'string' ? input.body : '';
      const comment: IssueComment = {
        id: repo.nextCommentId++,
        body: text,
        user: VIEWER.login,
        createdAt: isoOf(nextTimestamp()),
        seq: storeSeq++,
      };
      issue.comments.push(comment);
      sendJson(res, 201, commentJson(repo, issue, comment));
      return;
    }
    if (method === 'GET') {
      sendJson(res, 200, issue.comments.map((c) => commentJson(repo, issue, c)));
      return;
    }
    notFound(res);
    return;
  }

  notFound(res);
}

async function handlePulls(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  rest: string[],
  body: Buffer,
  query: URLSearchParams,
): Promise<void> {
  const method = req.method ?? 'GET';

  if (rest.length === 0) {
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        sendJson(res, 400, { message: parsed.error });
        return;
      }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const title = typeof input.title === 'string' ? input.title : '';
      const bodyText = typeof input.body === 'string' ? input.body : '';
      const head = typeof input.head === 'string' ? input.head : '';
      const base = typeof input.base === 'string' ? input.base : repo.defaultBranch;
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) {
        sendJson(res, 422, { message: 'Validation Failed: head and base branches must exist' });
        return;
      }
      const existing = repo.pulls.find((p) => p.head === head && p.base === base && p.state === 'open');
      if (existing) {
        sendJson(res, 422, { message: 'Validation Failed: a pull request already exists for this head branch' });
        return;
      }
      const ts = nextTimestamp();
      const pull: PullRequest = {
        number: repo.nextNumber++,
        title,
        body: bodyText,
        state: 'open',
        head,
        base,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        createdSeq: storeSeq++,
        createdAt: isoOf(ts),
        updatedAt: isoOf(ts),
      };
      repo.pulls.push(pull);
      sendJson(res, 201, pullJson(repo, pull));
      return;
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      let list = [...repo.pulls];
      if (state !== 'all') list = list.filter((p) => p.state === state);
      list.sort((a, b) => b.createdSeq - a.createdSeq);
      const { page } = paginate(list, query);
      sendJson(res, 200, page.map((p) => pullJson(repo, p)));
      return;
    }
    notFound(res);
    return;
  }

  const number = Number(rest[0]);
  if (!Number.isInteger(number)) {
    notFound(res);
    return;
  }
  const pull = repo.pulls.find((p) => p.number === number);
  if (!pull) {
    notFound(res);
    return;
  }

  if (rest.length === 1 && method === 'GET') {
    sendJson(res, 200, pullJson(repo, pull));
    return;
  }

  if (rest.length === 2 && rest[1] === 'files' && method === 'GET') {
    const baseTree = treeOfCommit(repo, pull.baseSha);
    const headTree = treeOfCommit(repo, pull.headSha);
    const diff = diffTrees(repo, baseTree, headTree);
    const files = diff.map((d) => {
      const counts = lineCounts(repo, d.oldOid, d.newOid);
      return {
        filename: d.path,
        status: d.status,
        additions: counts.additions,
        deletions: counts.deletions,
        changes: counts.additions + counts.deletions,
        sha: d.newOid ?? d.oldOid,
      };
    });
    sendJson(res, 200, files);
    return;
  }

  if (rest.length === 2 && rest[1] === 'merge' && method === 'PUT') {
    if (pull.state !== 'open') {
      sendJson(res, 405, { message: 'Pull request is already closed' });
      return;
    }
    const mergeOid = squashMerge(repo, pull);
    if (!mergeOid) {
      sendJson(res, 405, { message: 'Merge conflict: this pull request cannot be merged' });
      return;
    }
    sendJson(res, 200, { merged: true, sha: mergeOid, message: 'Pull request successfully merged' });
    return;
  }

  notFound(res);
}

// -------------------------------------------------------------------------------------------
// GraphQL v4 (/api/graphql) — a small executor for the documents gh sends
// -------------------------------------------------------------------------------------------

interface GqlSelection {
  alias: string | null;
  name: string;
  args: Record<string, unknown>;
  children: GqlSelection[];
  fragmentType: string | null; // for inline fragments: the type condition
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
}

function tokenizeGql(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c) || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}():[]!=$'.includes(c)) {
      tokens.push(c);
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1]!;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j]!)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j]!)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: string[];
  private readonly variables: Record<string, unknown>;
  constructor(tokens: string[], variables: Record<string, unknown>) {
    this.tokens = tokens;
    this.variables = variables;
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }
  private next(): string {
    return this.tokens[this.pos++] ?? '';
  }
  private expect(tok: string): void {
    const got = this.next();
    if (got !== tok) throw new Error(`expected ${tok}, got ${got}`);
  }

  parseDocument(): GqlOperation[] {
    const ops: GqlOperation[] = [];
    while (this.pos < this.tokens.length) {
      const tok = this.next();
      if (tok === 'query' || tok === 'mutation') {
        let name: string | null = null;
        if (this.peek() !== undefined && this.peek() !== '{' && this.peek() !== '(') name = this.next();
        if (this.peek() === '(') this.skipParens();
        const selections = this.parseSelectionSet();
        ops.push({ kind: tok, name, selections });
      } else if (tok === '{') {
        this.pos -= 1;
        ops.push({ kind: 'query', name: null, selections: this.parseSelectionSet() });
      } else {
        // fragment definitions etc.: skip (not used by the suite's documents)
        if (this.peek() === '{') this.parseSelectionSet();
      }
    }
    return ops;
  }

  private skipParens(): void {
    this.expect('(');
    let depth = 1;
    while (this.pos < this.tokens.length && depth > 0) {
      const t = this.next();
      if (t === '(' || t === '[' || t === '{') depth += 1;
      else if (t === ')' || t === ']' || t === '}') depth -= 1;
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== undefined && this.peek() !== '}') {
      out.push(...this.parseSelection());
    }
    this.expect('}');
    return out;
  }

  private parseSelection(): GqlSelection[] {
    const tok = this.next();
    if (tok === '...') {
      // Inline fragment: `... on Type { ... }` (fragment spreads are not used).
      let fragmentType: string | null = null;
      if (this.peek() === 'on') {
        this.next();
        fragmentType = this.next();
      }
      const children = this.parseSelectionSet();
      return children.map((c) => ({ ...c, fragmentType }));
    }
    let alias: string | null = null;
    let name = tok;
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    let args: Record<string, unknown> = {};
    if (this.peek() === '(') args = this.parseArguments();
    let children: GqlSelection[] = [];
    if (this.peek() === '{') children = this.parseSelectionSet();
    return [{ alias, name, args, children, fragmentType: null }];
  }

  private parseArguments(): Record<string, unknown> {
    this.expect('(');
    const args: Record<string, unknown> = {};
    while (this.peek() !== undefined && this.peek() !== ')') {
      const key = this.next();
      this.expect(':');
      args[key] = this.parseValue();
    }
    this.expect(')');
    return args;
  }

  private parseValue(): unknown {
    const tok = this.next();
    if (tok === '$') {
      const name = this.next();
      return this.variables[name];
    }
    if (tok === '[') {
      const list: unknown[] = [];
      while (this.peek() !== undefined && this.peek() !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (tok === '{') {
      const obj: Record<string, unknown> = {};
      while (this.peek() !== undefined && this.peek() !== '}') {
        const key = this.next();
        this.expect(':');
        obj[key] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    if (tok.startsWith('"')) return JSON.parse(tok) as string;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    const num = Number(tok);
    if (tok !== '' && !Number.isNaN(num)) return num;
    return tok; // enum value
  }
}

// The static schema surface the introspection checks read.
const SCHEMA: Record<string, { fields: string[]; enumValues?: string[] }> = {
  Issue: { fields: ['id', 'number', 'title', 'state', 'body', 'author', 'createdAt', 'updatedAt', 'comments', 'labels', 'url', 'repository'] },
  PullRequest: { fields: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergedAt', 'mergeCommitSha', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'mergeable', 'files', 'author', 'createdAt', 'updatedAt', 'url'] },
  Repository: { fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'createdAt', 'updatedAt'] },
  SearchType: { fields: [], enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'] },
  User: { fields: ['id', 'login', 'name', 'email'] },
  IssueConnection: { fields: ['nodes', 'pageInfo', 'totalCount'] },
  PullRequestConnection: { fields: ['nodes', 'pageInfo', 'totalCount'] },
  IssueComment: { fields: ['id', 'body', 'author', 'createdAt'] },
};

interface GqlContext {
  errors: Array<{ message: string }>;
}

function gqlError(ctx: GqlContext, message: string): void {
  ctx.errors.push({ message });
}

function applySelections(
  ctx: GqlContext,
  typename: string,
  allowed: string[],
  values: Record<string, unknown>,
  selections: GqlSelection[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.fragmentType !== null && sel.fragmentType !== typename) continue;
    const key = sel.alias ?? sel.name;
    if (!allowed.includes(sel.name)) {
      gqlError(ctx, `Cannot query field "${sel.name}" on type "${typename}".`);
      continue;
    }
    out[key] = values[sel.name];
  }
  return out;
}

function cursorFor(number: number): string {
  return b64encode(`cursor:${number}`);
}
function numberFromCursor(cursor: string): number | null {
  try {
    const text = b64decode(cursor).toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

function issueNode(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    state: issue.state.toUpperCase(),
    body: issue.body,
  };
}

function pullNode(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    id: globalId('PullRequest', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state.toUpperCase(),
    merged: pull.merged,
    mergedAt: pull.mergedAt,
    headRefName: pull.head,
    baseRefName: pull.base,
    mergeable: mergeableState(repo, pull),
  };
}

function resolveRepository(ctx: GqlContext, repo: Repo, selections: GqlSelection[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.fragmentType !== null && sel.fragmentType !== 'Repository') continue;
    const key = sel.alias ?? sel.name;
    switch (sel.name) {
      case 'id':
        out[key] = globalId('Repository', repo.id, 0);
        break;
      case 'databaseId':
        out[key] = repo.id;
        break;
      case 'name':
        out[key] = repo.name;
        break;
      case 'nameWithOwner':
        out[key] = `${repo.owner}/${repo.name}`;
        break;
      case 'owner':
        out[key] = applySelections(ctx, 'User', SCHEMA.User!.fields, { login: repo.owner, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email }, sel.children);
        break;
      case 'defaultBranchRef': {
        const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        out[key] = tip ? applySelections(ctx, 'Ref', ['name'], { name: repo.defaultBranch }, sel.children) : null;
        break;
      }
      case 'viewerPermission':
        out[key] = 'ADMIN';
        break;
      case 'hasIssuesEnabled':
        out[key] = true;
        break;
      case 'description':
        out[key] = repo.description;
        break;
      case 'issue': {
        const number = sel.args.number as number | undefined;
        const issue = repo.issues.find((i) => i.number === number);
        out[key] = issue ? resolveIssue(ctx, repo, issue, sel.children) : null;
        break;
      }
      case 'issues': {
        out[key] = resolveIssuesConnection(ctx, repo, sel);
        break;
      }
      case 'pullRequests': {
        const first = typeof sel.args.first === 'number' ? sel.args.first : 100;
        const nodes = [...repo.pulls].sort((a, b) => b.createdSeq - a.createdSeq).slice(0, first);
        const conn: Record<string, unknown> = {};
        for (const child of sel.children) {
          if (child.name === 'nodes') conn.nodes = nodes.map((p) => resolvePullRequest(ctx, repo, p, child.children));
          else if (child.name === 'pageInfo') conn.pageInfo = applySelections(ctx, 'PageInfo', ['hasNextPage', 'endCursor'], { hasNextPage: false, endCursor: null }, child.children);
          else if (child.name === 'totalCount') conn.totalCount = repo.pulls.length;
          else gqlError(ctx, `Cannot query field "${child.name}" on type "PullRequestConnection".`);
        }
        out[key] = conn;
        break;
      }
      case 'pullRequest': {
        const number = sel.args.number as number | undefined;
        const pull = repo.pulls.find((p) => p.number === number);
        out[key] = pull ? resolvePullRequest(ctx, repo, pull, sel.children) : null;
        break;
      }
      default:
        gqlError(ctx, `Cannot query field "${sel.name}" on type "Repository".`);
        break;
    }
  }
  return out;
}

function resolveIssue(ctx: GqlContext, repo: Repo, issue: Issue, selections: GqlSelection[]): Record<string, unknown> {
  return applySelections(ctx, 'Issue', SCHEMA.Issue!.fields, issueNode(repo, issue), selections);
}

function resolveIssuesConnection(ctx: GqlContext, repo: Repo, sel: GqlSelection): Record<string, unknown> {
  const first = typeof sel.args.first === 'number' ? sel.args.first : 100;
  const after = typeof sel.args.after === 'string' ? numberFromCursor(sel.args.after) : null;
  const states = Array.isArray(sel.args.states) ? (sel.args.states as string[]) : null;
  const orderBy = isRecord(sel.args.orderBy) ? sel.args.orderBy : null;
  let list = [...repo.issues];
  if (states) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => wanted.has(i.state));
  }
  const direction = orderBy && String(orderBy.direction ?? '').toUpperCase() === 'ASC' ? 'asc' : 'desc';
  list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
  if (after !== null) {
    // `after` names the last number seen on the previous page (creation order is by number here).
    list = list.filter((i) => (direction === 'asc' ? i.number > after : i.number < after));
    // Re-sort to the requested direction after filtering (filtering by number works because
    // numbers increase with creation order).
    list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
  }
  const page = list.slice(0, first);
  const hasNextPage = list.length > first;
  const endCursor = page.length ? cursorFor(page[page.length - 1]!.number) : null;
  const conn: Record<string, unknown> = {};
  for (const child of sel.children) {
    if (child.name === 'nodes') conn.nodes = page.map((i) => resolveIssue(ctx, repo, i, child.children));
    else if (child.name === 'pageInfo') conn.pageInfo = applySelections(ctx, 'PageInfo', ['hasNextPage', 'endCursor'], { hasNextPage, endCursor }, child.children);
    else if (child.name === 'totalCount') conn.totalCount = list.length;
    else gqlError(ctx, `Cannot query field "${child.name}" on type "IssueConnection".`);
  }
  return conn;
}

function resolvePullRequest(ctx: GqlContext, repo: Repo, pull: PullRequest, selections: GqlSelection[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.fragmentType !== null && sel.fragmentType !== 'PullRequest') continue;
    const key = sel.alias ?? sel.name;
    if (sel.name === 'files') {
      const first = typeof sel.args.first === 'number' ? sel.args.first : 100;
      const baseTree = treeOfCommit(repo, pull.baseSha);
      const headTree = treeOfCommit(repo, pull.headSha);
      const diff = diffTrees(repo, baseTree, headTree).slice(0, first);
      const conn: Record<string, unknown> = {};
      for (const child of sel.children) {
        if (child.name === 'nodes') {
          conn.nodes = diff.map((d) => applySelections(ctx, 'PullRequestChangedFile', ['path'], { path: d.path }, child.children));
        } else if (child.name === 'pageInfo') {
          conn.pageInfo = applySelections(ctx, 'PageInfo', ['hasNextPage', 'endCursor'], { hasNextPage: false, endCursor: null }, child.children);
        } else {
          gqlError(ctx, `Cannot query field "${child.name}" on type "PullRequestChangedFileConnection".`);
        }
      }
      out[key] = conn;
      continue;
    }
    const values = pullNode(repo, pull);
    if (!(sel.name in values) && !SCHEMA.PullRequest!.fields.includes(sel.name)) {
      gqlError(ctx, `Cannot query field "${sel.name}" on type "PullRequest".`);
      continue;
    }
    out[key] = values[sel.name];
  }
  return out;
}

function resolveTypeIntrospection(ctx: GqlContext, name: string, selections: GqlSelection[]): Record<string, unknown> | null {
  const type = SCHEMA[name];
  if (!type) return null;
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    const key = sel.alias ?? sel.name;
    if (sel.name === 'fields') {
      out[key] = type.fields.map((f) => applySelections(ctx, '__Field', ['name'], { name: f }, sel.children));
    } else if (sel.name === 'enumValues') {
      out[key] = (type.enumValues ?? []).map((v) => applySelections(ctx, '__EnumValue', ['name'], { name: v }, sel.children));
    } else if (sel.name === 'name') {
      out[key] = name;
    } else {
      gqlError(ctx, `Cannot query field "${sel.name}" on type "__Type".`);
    }
  }
  return out;
}

function executeOperation(op: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown>; errors: Array<{ message: string }> } {
  const ctx: GqlContext = { errors: [] };
  const data: Record<string, unknown> = {};
  for (const sel of op.selections) {
    const key = sel.alias ?? sel.name;
    if (op.kind === 'query') {
      switch (sel.name) {
        case 'viewer':
          data[key] = applySelections(ctx, 'User', SCHEMA.User!.fields, { login: VIEWER.login, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email }, sel.children);
          break;
        case 'repository': {
          const owner = String(sel.args.owner ?? '');
          const name = String(sel.args.name ?? '');
          const repo = owner === VIEWER.login ? findRepo(owner, name) : null;
          data[key] = repo ? resolveRepository(ctx, repo, sel.children) : null;
          break;
        }
        case 'node': {
          const id = String(sel.args.id ?? '');
          const parsed = parseGlobalId(id);
          let node: Record<string, unknown> | null = null;
          if (parsed?.kind === 'Repository') {
            const repo = repoById(parsed.repoId);
            if (repo) {
              node = { id, __typename: 'Repository' };
              for (const child of sel.children) {
                if (child.fragmentType !== null && child.fragmentType !== 'Repository') continue;
                if (child.name === 'id') node.id = id;
                else if (child.name === 'name') node.name = repo.name;
                else if (child.name === 'nameWithOwner') node.nameWithOwner = `${repo.owner}/${repo.name}`;
                else gqlError(ctx, `Cannot query field "${child.name}" on type "Repository".`);
              }
            }
          }
          data[key] = node;
          break;
        }
        case '__type': {
          const name = String(sel.args.name ?? '');
          data[key] = resolveTypeIntrospection(ctx, name, sel.children);
          break;
        }
        default:
          gqlError(ctx, `Cannot query field "${sel.name}" on type "Query".`);
          break;
      }
    } else {
      // Mutations.
      const input = isRecord(sel.args.input) ? sel.args.input : {};
      switch (sel.name) {
        case 'createIssue': {
          const parsed = parseGlobalId(String(input.repositoryId ?? ''));
          const repo = parsed?.kind === 'Repository' ? repoById(parsed.repoId) : null;
          if (!repo) {
            gqlError(ctx, 'createIssue: repository not found');
            data[key] = { issue: null };
            break;
          }
          const ts = nextTimestamp();
          const issue: Issue = {
            number: repo.nextNumber++,
            title: String(input.title ?? ''),
            body: String(input.body ?? ''),
            state: 'open',
            labels: [],
            comments: [],
            createdSeq: storeSeq++,
            createdAt: isoOf(ts),
            updatedAt: isoOf(ts),
          };
          repo.issues.push(issue);
          const issueSel = sel.children.find((c) => c.name === 'issue');
          data[key] = { issue: issueSel ? resolveIssue(ctx, repo, issue, issueSel.children) : null };
          break;
        }
        case 'closeIssue': {
          const parsed = parseGlobalId(String(input.issueId ?? ''));
          const repo = parsed?.kind === 'Issue' ? repoById(parsed.repoId) : null;
          const issue = repo?.issues.find((i) => i.number === parsed?.n);
          if (!issue || !repo) {
            gqlError(ctx, 'closeIssue: issue not found');
            data[key] = { issue: null };
            break;
          }
          issue.state = 'closed';
          issue.updatedAt = isoOf(nextTimestamp());
          const issueSel = sel.children.find((c) => c.name === 'issue');
          data[key] = { issue: issueSel ? resolveIssue(ctx, repo, issue, issueSel.children) : null };
          break;
        }
        case 'createPullRequest': {
          const parsed = parseGlobalId(String(input.repositoryId ?? ''));
          const repo = parsed?.kind === 'Repository' ? repoById(parsed.repoId) : null;
          const head = String(input.headRefName ?? '');
          const base = String(input.baseRefName ?? '');
          const headSha = repo?.refs.get(`refs/heads/${head}`);
          const baseSha = repo?.refs.get(`refs/heads/${base}`);
          if (!repo || !headSha || !baseSha) {
            gqlError(ctx, 'createPullRequest: repository or branches not found');
            data[key] = { pullRequest: null };
            break;
          }
          const ts = nextTimestamp();
          const pull: PullRequest = {
            number: repo.nextNumber++,
            title: String(input.title ?? ''),
            body: String(input.body ?? ''),
            state: 'open',
            head,
            base,
            headSha,
            baseSha,
            merged: false,
            mergedAt: null,
            mergeCommitSha: null,
            createdSeq: storeSeq++,
            createdAt: isoOf(ts),
            updatedAt: isoOf(ts),
          };
          repo.pulls.push(pull);
          const prSel = sel.children.find((c) => c.name === 'pullRequest');
          data[key] = { pullRequest: prSel ? resolvePullRequest(ctx, repo, pull, prSel.children) : null };
          break;
        }
        case 'mergePullRequest': {
          const parsed = parseGlobalId(String(input.pullRequestId ?? ''));
          const repo = parsed?.kind === 'PullRequest' ? repoById(parsed.repoId) : null;
          const pull = repo?.pulls.find((p) => p.number === parsed?.n);
          if (!pull || !repo) {
            gqlError(ctx, 'mergePullRequest: pull request not found');
            data[key] = { pullRequest: null };
            break;
          }
          if (pull.state === 'open') squashMerge(repo, pull);
          const prSel = sel.children.find((c) => c.name === 'pullRequest');
          data[key] = { pullRequest: prSel ? resolvePullRequest(ctx, repo, pull, prSel.children) : null };
          break;
        }
        case 'addComment': {
          const parsed = parseGlobalId(String(input.subjectId ?? ''));
          const repo = parsed?.kind === 'Issue' ? repoById(parsed.repoId) : null;
          const issue = repo?.issues.find((i) => i.number === parsed?.n);
          if (!issue || !repo) {
            gqlError(ctx, 'addComment: issue not found');
            data[key] = { commentEdge: null };
            break;
          }
          const comment: IssueComment = {
            id: repo.nextCommentId++,
            body: String(input.body ?? ''),
            user: VIEWER.login,
            createdAt: isoOf(nextTimestamp()),
            seq: storeSeq++,
          };
          issue.comments.push(comment);
          const edgeSel = sel.children.find((c) => c.name === 'commentEdge');
          const nodeSel = edgeSel?.children.find((c) => c.name === 'node');
          data[key] = {
            commentEdge: {
              node: nodeSel
                ? applySelections(ctx, 'IssueComment', SCHEMA.IssueComment!.fields, { id: globalId('IssueComment', repo.id, issue.number, `:${comment.id}`), body: comment.body }, nodeSel.children)
                : null,
            },
          };
          break;
        }
        default:
          gqlError(ctx, `Cannot query field "${sel.name}" on type "Mutation".`);
          break;
      }
    }
  }
  return { data, errors: ctx.errors };
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  if (!tokenIsValid(bearerToken(req))) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    sendJson(res, 400, { message: parsed.error });
    return;
  }
  const runOne = (doc: unknown): Record<string, unknown> => {
    if (!isRecord(doc) || typeof doc.query !== 'string') {
      return { errors: [{ message: 'A GraphQL operation must carry a query string' }] };
    }
    const variables = isRecord(doc.variables) ? (doc.variables as Record<string, unknown>) : {};
    let ops: GqlOperation[];
    try {
      ops = new GqlParser(tokenizeGql(doc.query), variables).parseDocument();
    } catch (err) {
      return { errors: [{ message: err instanceof Error ? err.message : 'Failed to parse the query' }] };
    }
    const op = typeof doc.operationName === 'string' ? ops.find((o) => o.name === doc.operationName) ?? ops[0] : ops[0];
    if (!op) return { errors: [{ message: 'No operation found in the document' }] };
    const result = executeOperation(op, variables);
    const out: Record<string, unknown> = { data: result.data };
    if (result.errors.length) out.errors = result.errors;
    return out;
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(parsed.value));
}

// -------------------------------------------------------------------------------------------
// MCP (Streamable HTTP, 2026-07-28 era + legacy initialize fallback) at /mcp
// -------------------------------------------------------------------------------------------

const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}
function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}
function mcpToolResult(payload: unknown, isError = false): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: typeof payload === 'string' ? payload : JSON.stringify(payload) }],
    structuredContent: payload,
    isError,
  };
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (!tool) return mcpToolResult({ error: `Unknown tool: ${name}` }, true);
  const required = (tool.inputSchema.required as string[]) ?? [];
  const missing = required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
  if (missing.length) return mcpToolResult({ error: `Missing required argument(s): ${missing.join(', ')}` }, true);
  const owner = String(args.owner ?? VIEWER.login);
  const repoName = String(args.repo ?? args.name ?? '');
  switch (name) {
    case 'create_repo': {
      const repo = findRepo(VIEWER.login, String(args.name));
      if (repo) return mcpToolResult(repoJson(repo));
      const created = createRepoRecord(VIEWER.login, String(args.name), args.private === true, typeof args.description === 'string' ? args.description : '');
      return mcpToolResult(repoJson(created));
    }
    case 'get_repo': {
      const repo = restRepo(owner, repoName);
      if (!repo) return mcpToolResult({ error: `Repository not found: ${owner}/${repoName}` }, true);
      return mcpToolResult(repoJson(repo));
    }
    case 'create_issue': {
      const repo = restRepo(owner, repoName);
      if (!repo) return mcpToolResult({ error: `Repository not found: ${owner}/${repoName}` }, true);
      const ts = nextTimestamp();
      const issue: Issue = {
        number: repo.nextNumber++,
        title: String(args.title ?? ''),
        body: String(args.body ?? ''),
        state: 'open',
        labels: [],
        comments: [],
        createdSeq: storeSeq++,
        createdAt: isoOf(ts),
        updatedAt: isoOf(ts),
      };
      repo.issues.push(issue);
      return mcpToolResult(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = restRepo(owner, repoName);
      if (!repo) return mcpToolResult({ error: `Repository not found: ${owner}/${repoName}` }, true);
      const state = String(args.state ?? 'open');
      let list = [...repo.issues];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => b.createdSeq - a.createdSeq);
      return mcpToolResult(list.map((i) => issueJson(repo, i)));
    }
    case 'create_pull_request': {
      const repo = restRepo(owner, repoName);
      if (!repo) return mcpToolResult({ error: `Repository not found: ${owner}/${repoName}` }, true);
      const head = String(args.head ?? '');
      const base = String(args.base ?? repo.defaultBranch);
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) return mcpToolResult({ error: 'Head and base branches must exist' }, true);
      const ts = nextTimestamp();
      const pull: PullRequest = {
        number: repo.nextNumber++,
        title: String(args.title ?? ''),
        body: String(args.body ?? ''),
        state: 'open',
        head,
        base,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        createdSeq: storeSeq++,
        createdAt: isoOf(ts),
        updatedAt: isoOf(ts),
      };
      repo.pulls.push(pull);
      return mcpToolResult(pullJson(repo, pull));
    }
    case 'merge_pull_request': {
      const repo = restRepo(owner, repoName);
      if (!repo) return mcpToolResult({ error: `Repository not found: ${owner}/${repoName}` }, true);
      const number = Number(args.pull_number);
      const pull = repo.pulls.find((p) => p.number === number);
      if (!pull) return mcpToolResult({ error: `Pull request not found: #${number}` }, true);
      if (pull.state !== 'open') return mcpToolResult({ error: 'Pull request is already closed' }, true);
      const mergeOid = squashMerge(repo, pull);
      if (!mergeOid) return mcpToolResult({ error: 'Merge conflict: this pull request cannot be merged' }, true);
      return mcpToolResult({ merged: true, sha: mergeOid, number: pull.number, state: pull.state });
    }
    default:
      return mcpToolResult({ error: `Unknown tool: ${name}` }, true);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  const method = req.method ?? 'POST';
  if (method === 'DELETE') {
    sendJson(res, 200, {});
    return;
  }
  if (method !== 'POST') {
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  // A body that is not JSON is a JSON-RPC parse error: HTTP 400, -32700.
  let parsed: unknown;
  try {
    parsed = body.length === 0 ? null : (JSON.parse(body.toString('utf8')) as unknown);
  } catch {
    sendJson(res, 400, mcpError(null, -32700, 'Parse error'));
    return;
  }
  if (!isRecord(parsed) || typeof parsed.method !== 'string') {
    sendJson(res, 400, mcpError(isRecord(parsed) ? parsed.id : null, -32600, 'Invalid Request'));
    return;
  }
  const id = parsed.id ?? null;
  // Notifications carry no id and get no answer body.
  if (id === null && parsed.method.startsWith('notifications/')) {
    sendNoContent(res, 202);
    return;
  }
  if (!tokenIsValid(bearerToken(req))) {
    sendJson(res, 401, mcpError(id, -32001, 'Unauthorized'));
    return;
  }
  const params = isRecord(parsed.params) ? parsed.params : {};
  switch (parsed.method) {
    case 'server/discover': {
      sendJson(res, 200, mcpResult(id, {
        supportedVersions: ['2026-07-28'],
        capabilities: { tools: {} },
        serverInfo: { name: 'git-forge', version: '1.0.0' },
        instructions: 'A GitHub-compatible git forge: git smart HTTP, REST v3, GraphQL v4 and MCP tools.',
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'git-forge', version: '1.0.0' } },
      }));
      return;
    }
    case 'initialize': {
      const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
      const negotiated = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(requested) ? requested : '2025-11-25';
      sendJson(res, 200, mcpResult(id, {
        protocolVersion: negotiated,
        capabilities: { tools: {} },
        serverInfo: { name: 'git-forge', version: '1.0.0' },
      }));
      return;
    }
    case 'tools/list': {
      sendJson(res, 200, mcpResult(id, { tools: MCP_TOOLS }));
      return;
    }
    case 'tools/call': {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
      const tool = MCP_TOOLS.find((t) => t.name === toolName);
      if (!tool) {
        sendJson(res, 200, mcpError(id, -32602, `Unknown tool: ${toolName}`));
        return;
      }
      const required = (tool.inputSchema.required as string[]) ?? [];
      const missing = required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
      if (missing.length) {
        sendJson(res, 200, mcpError(id, -32602, `Invalid params: missing required argument(s): ${missing.join(', ')}`));
        return;
      }
      sendJson(res, 200, mcpResult(id, mcpCallTool(toolName, args)));
      return;
    }
    default: {
      if (parsed.method.startsWith('notifications/')) {
        sendNoContent(res, 202);
        return;
      }
      sendJson(res, 200, mcpError(id, -32601, `Method not found: ${parsed.method}`));
      return;
    }
  }
}

// -------------------------------------------------------------------------------------------
// Router + app
// -------------------------------------------------------------------------------------------

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const path = pathOf(req);
        const method = req.method ?? 'GET';
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (path === '/api/graphql' || path === '/api/graphql/') {
          const body = await readBody(req);
          await handleGraphQL(req, res, body);
          return;
        }
        if (path === '/mcp' || path === '/mcp/') {
          const body = await readBody(req);
          await handleMcp(req, res, body);
          return;
        }
        if (path.startsWith('/api/v3')) {
          const body = await readBody(req);
          await handleRest(req, res, path, body);
          return;
        }
        // Git smart HTTP: /{owner}/{repo}.git/... (the .git suffix is the suite's spelling;
        // the bare form is accepted too).
        const gitMatch = /^\/([^/]+)\/([^/]+?)(?:\.git)?\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
        if (gitMatch) {
          const owner = decodeURIComponent(gitMatch[1]!);
          const repoName = decodeURIComponent(gitMatch[2]!);
          const endpoint = gitMatch[3]!;
          if (endpoint === 'info/refs' && method === 'GET') {
            const service = queryOf(req).get('service') ?? '';
            handleInfoRefs(req, res, owner, repoName, service);
            return;
          }
          if (endpoint === 'git-upload-pack' && method === 'POST') {
            const body = await readBody(req);
            handleUploadPack(req, res, owner, repoName, body);
            return;
          }
          if (endpoint === 'git-receive-pack' && method === 'POST') {
            const body = await readBody(req);
            handleReceivePack(req, res, owner, repoName, body);
            return;
          }
        }
        sendJson(res, 404, { message: 'Not Found' });
      } catch (err) {
        // Never die on a request: answer 500 JSON and stay up.
        try {
          sendJson(res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
        } catch {
          // The socket is already gone; nothing more to do.
        }
      }
    })();
  });
}

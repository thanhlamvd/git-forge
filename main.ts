// How this process lives and dies, following the env's wire protocol: grab a free port, hand it to
// the env so the suite can reach the forge, then keep asking whether the trial has finished and
// leave with code 0 once it has. Nothing here serves requests — that is app.ts's job; this file
// only runs the handshake with the environment that grades the server.
// The handshake, in order:
//   1. MAKEFUN_ENV_URL points at the env (in a trial container it is http://store:8080). With no
//      URL there is nobody to register with, so the process stops with code 1 right away.
//   2. Build the forge and listen on port 0, letting the kernel choose. Port 8080 stays the env's.
//   3. POST $MAKEFUN_ENV_URL/register with {"port": N}. The env notes where the request arrived
//      from plus N and dials the forge from then on. Whoever registers first wins; a 409 means
//      another entry got there first, and this process simply carries on waiting.
//   4. GET $MAKEFUN_ENV_URL/done until it answers {"done": true}. The env replies at once (false
//      while the suite is still running), so this is a poll. A failed or slow poll is retried with
//      a short backoff that grows; the process never leaves before the env says done.
//   5. Shut the server and leave with code 0. The harness then stops the env, which writes the
//      export the scorer reads.
// Only the forge itself is imported here: no other package, no Node built-in, no model call.

import { createApp as buildServer } from './app.ts';

/** Stop the process with the given code, from anywhere in this file. */
const quit = (code: number): never => process.exit(code);

/** The env's origin, with any trailing slashes stripped off. */
const envOrigin = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envOrigin === '') { process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with' + '\n'); quit(1); }

/** The longest one register or done request may run before it is dropped and retried. */
const REQUEST_LIMIT_MS = 30_000;
/** The first pause between retries, and the longest pause. */
const RETRY_START_MS = 250;
const RETRY_CAP_MS = 2_000;

/** Wait `ms` milliseconds. */
const pause = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/** The pause after `attempt` failed requests: doubling from RETRY_START_MS, capped. */
const backoff = (attempt: number): number => Math.min(RETRY_CAP_MS, RETRY_START_MS * 2 ** Math.min(attempt, 8));

// Tell the env which port the forge bound, retrying until it sticks. 200 is the usual answer;
// 409 means an earlier register already won, which this process cannot change. 400 and 405 are
// contract errors and stop the program; a network error or any other status is retried, since
// the env may still be coming up.
const onRegisterReply = async (res: Response): Promise<'registered' | 'retry'> => {
  if (res.status === 200 || res.status === 409) return 'registered';
  if (res.status === 400 || res.status === 405) throw new Error('register answered HTTP ' + res.status + ': ' + (await res.text()));
  return 'retry';
};
const onRegisterError = (err: unknown): 'retry' => {
  const fatal = err instanceof Error && err.message.indexOf('register answered HTTP ') === 0;
  if (fatal) throw err;
  return 'retry';
};
const announce = async (port: number): Promise<void> => {
  let attempt = 0;
  while (true) {
    const outcome = await fetch(envOrigin + '/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ port }), signal: AbortSignal.timeout(REQUEST_LIMIT_MS) }).then(onRegisterReply).catch(onRegisterError);
    if (outcome === 'registered') return;
    await pause(backoff(attempt));
    attempt += 1;
  };
};

// Ask GET /done until it answers {"done": true}; never come back before that.
const onDoneReply = async (res: Response): Promise<boolean> => res.ok && (await res.json() as { done?: unknown }).done === true;
const pollDone = async (): Promise<void> => {
  let attempt = 0;
  while (true) {
    const finished = await fetch(envOrigin + '/done', { signal: AbortSignal.timeout(REQUEST_LIMIT_MS) }).then(onDoneReply).catch(() => false);
    if (finished) return;
    await pause(backoff(attempt));
    attempt += 1;
  };
};

// Bind the port, register it, then wait for the env: the whole life of the process.
const boot = async (): Promise<void> => {
  const server = buildServer();
  await new Promise<void>((ok, fail) => { server.once('error', fail); server.listen(0, () => ok()); });
  const bound = server.address();
  if (bound === null || typeof bound === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] listening on port ${bound.port}\n`);
  await announce(bound.port);
  process.stdout.write('[entry] registered; waiting for the env to say done' + '\n');
  await pollDone();
  server.close(); process.stdout.write('[entry] done' + '\n');
};

const onBootOk = (): never => quit(0);
const onBootFail = (err: unknown): never => {
  const why = err instanceof Error ? err.message : String(err);
  process.stderr.write('[entry] ' + why + '\n');
  return quit(1);
};
boot().then(onBootOk, onBootFail);

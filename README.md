# git-forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/thanhlamvd/git-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/thanhlamvd/git-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single Node 22 process, standard library only — no git binary, no dependencies, no database. It speaks the git smart-HTTP protocol (upload-pack v2 with shallow fetch/deepen, receive-pack v0 with report-status and side-band-64k), the REST v3 API (repos, issues, pull requests with squash merge, contents, commits, branches), GraphQL (viewer, repository, issues, pull requests, mutations, introspection, batched operations, opaque global ids), and MCP (modern `server/discover` plus legacy `initialize`, six tools). The object store is SHA-1 git objects in memory with pack v2 read/write, OFS/REF delta resolution on input, and a one-inflate pack reader. Locally it passes all 120 conformance checks (feature 600/600, agent 200/200) and scores ~980/1000 with the kit's benchmark.

## Run it

```sh
npm start
```

---

<sub>Entered on [make.fun](https://make.fun/?ref=814bp22d&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>

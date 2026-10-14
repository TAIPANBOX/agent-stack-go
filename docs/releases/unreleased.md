# agent-stack-go, unreleased

Changes on `main` since 1.2.0 that no tag carries yet. The version that ships
them is decided when the tag is cut; nothing in the exported surface moved, so
`scripts/api-surface.sh` holds `api/surface.txt` at its 143 declarations.

## Fixed: a plain Writer takes the file lock that a shared stream needs

- **`event.Writer` appends under an exclusive `flock(2)` on the file.** Until
  now only `ChainedWriter` locked the file. A plain `Writer` that another
  process also appends to has the same unlocked append, and on an NFS share two
  appends can overwrite one another. The chained writer's unlocked append lost
  half of two writers' events on a shared volume, measured on 2026-10-14
  (see 1.2.0). The plain writer was not measured on its own.
- Concurrent callers inside one process were already serialized by a mutex; that
  stays. The lock adds exclusion between processes.

## Behaviour a consumer can notice

- `Write` returns an error and appends nothing when the file cannot be locked.
- `Write` blocks while another writer of the same file holds the lock, for as
  long as that writer's append takes.
- An error from releasing the lock is returned although the line is on disk.
- On Windows there is no cross-process lock, as before. No bus runs there.

## Upgrade notes

- No code change for a consumer: no exported identifier changed. A service that
  writes a shared stream with `event.Writer` (not `ChainedWriter`) should move
  to the next tag, so that its appends are serialized with the other writers of
  the file.

## Not proven

- The lock is verified by probes from a second open file of the same path, which
  flock excludes as a second process would. A cross-process loss on a real NFS
  share was not reproduced for the plain writer in this change.
- Durability: `Write` does not fsync, as before.

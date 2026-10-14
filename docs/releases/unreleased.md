# agent-stack-go, unreleased

Changes on `main` since 1.1.0 that no tag carries yet. The version that ships
them is decided when the tag is cut; nothing in the exported surface moved, so
`scripts/api-surface.sh` holds `api/surface.txt` unchanged.

## Fixed: writers sharing one stream keep one chain

- **`event.ChainedWriter` stamps `prev_hash` from the file, under a lock on
  the file.** Every `Write` takes an exclusive `flock(2)`, reads the last line
  on disk, stamps `prev_hash` from it, appends, and unlocks. Until now a writer
  chained from the hash of its own previous write, held in memory, which is
  right only while it is the file's only writer. On a shared events bus it is
  not: a pod being replaced keeps appending through its grace period while its
  successor has resumed the chain, and a service and its CronJob can share one
  stream. Each interleaving was reported as `chain_broken` on an honest stream.
- A stream whose last byte is not a newline (a writer killed mid-line) gets one
  before the next event, so the event is a line of its own and starts a fresh
  chain after the fragment: a restart, not a break.
- The writer now finds the last line by reading backwards from the end of the
  file, up to VerifyChain's own 4 MiB line cap (it was a fixed 1 MiB window).

## Behaviour a consumer can notice

- `NewChainedWriter` fails when the file cannot be locked at all, and `Write`
  returns an error and appends nothing when the lock cannot be taken or the
  end of the file cannot be read. An error from releasing the lock is returned
  although the line is on disk.
- `Write` blocks while another writer of the same file holds the lock, for as
  long as that writer's append takes.
- `ResumedFrom` still reports what the file held at open; it is no longer the
  value the next `Write` will chain from, because every `Write` reads the file.
- On Windows there is no cross-process lock, only the re-read of the tail.

## Upgrade notes

- No code change for a consumer: no exported identifier changed. Every service
  that appends to a stream another process also appends to (on the shared bus,
  that is every service whose pod can be replaced) needs the new version to
  stop false `chain_broken` reports.

## Not proven

- Durability: `Write` does not fsync, as before. A line written just before
  the host loses power may be lost; the next writer chains from whatever is
  last on disk, so the chain does not break.
- The NFS behaviour was measured on one storage stack (see the pull request);
  other network filesystems, and an NFS mount with `local_lock=flock` or
  `nolock`, keep the lock on one node only.

#!/usr/bin/env python3
"""
detector.py - Real-time detector for Pod Priority Preemption DoS activity.

Watches the Kubernetes Events API and logs scheduling-preemption signals to a
CSV. It focuses on the two events that a preemption-based DoS produces:

  * "Preempted"        - emitted by the scheduler on a VICTIM pod that was
                         evicted to make room for a higher-priority pod.
  * "FailedScheduling" - emitted on a pod that cannot be scheduled (e.g. a
                         victim that was recreated but is now stuck Pending,
                         or any pod starved of resources by the attack).

CSV columns (preemption_log.csv):
  timestamp               - event time (ISO-8601, local tz)
  namespace               - namespace of the affected pod
  evicted_pod_name        - the pod named in the event (victim / pending pod)
  reason                  - "Preempted" or "FailedScheduling"
  message                 - the raw event message
  preempting_pod          - the pod that caused the preemption, parsed from the
                            event message ("<ns>/<name>"); "unknown" if the API
                            does not expose it
  pending_duration_seconds- how long this pod has been Pending so far, measured
                            from the first time we saw it fail to schedule / be
                            preempted until this event. The maximum value logged
                            for a given pod is its total pending duration before
                            it was rescheduled or removed.

Usage:
  py detector.py            # watch forever, append to preemption_log.csv
  py detector.py --test     # connect, print cluster info, exit (no watch)
  py detector.py --csv FILE # use a different CSV path
  py detector.py --context CTX  # use a specific kube-context (default: current)
"""

import argparse
import csv
import datetime as dt
import os
import re
import signal
import sys

from kubernetes import client, config, watch

REASONS = {"Preempted", "FailedScheduling"}

# The scheduler's "Preempted" message comes in two shapes depending on
# version:
#   "Preempted by pod bad-tenant/evictor on node cep"   (namespace/name)
#   "Preempted by pod <uid> on node cep"                 (preemptor pod UID)
PREEMPTOR_NSNAME_RE = re.compile(
    r"Preempted by (?:pod )?([a-z0-9][a-z0-9.\-]*/[a-z0-9][a-z0-9.\-]*) on node")
PREEMPTOR_UID_RE = re.compile(
    r"Preempted by (?:pod )?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")


class UidResolver:
    """Resolves a pod UID to '<namespace>/<name>' with a refreshable cache."""

    def __init__(self, core):
        self.core = core
        self.cache = {}

    def _refresh(self):
        try:
            for p in self.core.list_pod_for_all_namespaces().items:
                self.cache[p.metadata.uid] = (
                    f"{p.metadata.namespace}/{p.metadata.name}")
        except Exception:
            pass

    def resolve(self, uid):
        if uid not in self.cache:
            self._refresh()
        # fall back to the raw UID (still better than "unknown")
        return self.cache.get(uid, uid)


def parse_preemptor(message, resolver=None):
    """Return the preempting pod identity, resolving a UID when possible."""
    if not message:
        return "unknown"
    m = PREEMPTOR_NSNAME_RE.search(message)
    if m:
        return m.group(1)
    m = PREEMPTOR_UID_RE.search(message)
    if m:
        uid = m.group(1)
        return resolver.resolve(uid) if resolver else uid
    return "unknown"


def now_local():
    return dt.datetime.now().astimezone()


def event_time(evt):
    """Best-effort timestamp for a core/v1 Event, as an aware datetime."""
    for attr in ("last_timestamp", "event_time", "first_timestamp"):
        val = getattr(evt, attr, None)
        if val is not None:
            # client returns tz-aware datetimes already
            return val if isinstance(val, dt.datetime) else now_local()
    meta = getattr(evt, "metadata", None)
    if meta is not None and getattr(meta, "creation_timestamp", None):
        return meta.creation_timestamp
    return now_local()


def ensure_csv(path):
    """Create the CSV with a header row if it does not exist yet."""
    header = [
        "timestamp", "namespace", "evicted_pod_name", "reason",
        "message", "preempting_pod", "pending_duration_seconds",
    ]
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)


def connect(context):
    """Load kube config (optionally a named context) and return CoreV1Api."""
    if context:
        config.load_kube_config(context=context)
    else:
        config.load_kube_config()
    return client.CoreV1Api()


def run_test(context):
    core = connect(context)
    ver = client.VersionApi(core.api_client).get_code()
    _, active = config.list_kube_config_contexts()
    ns = core.list_namespace()
    print(f"[OK] connected to context '{active['name']}' "
          f"(server k8s {ver.git_version})")
    print(f"[OK] can read API: {len(ns.items)} namespaces visible")
    print("[OK] detector dependencies and cluster access verified.")
    return 0


def run_watch(context, csv_path):
    core = connect(context)
    _, active = config.list_kube_config_contexts()
    ensure_csv(csv_path)

    # first time (seconds) we saw each pod in a pending/preempted situation
    first_pending = {}
    resolver = UidResolver(core)

    print(f"[detector] context='{active['name']}'  csv='{csv_path}'")
    print(f"[detector] watching Events for reasons {sorted(REASONS)} ... "
          f"(Ctrl-C to stop)")
    print(f"{'TIME':<23} {'REASON':<16} {'NAMESPACE':<12} {'POD':<28} "
          f"{'PENDING_s':>9}  PREEMPTOR")

    # Ignore events that occurred before the detector started (the watch may
    # replay recently-cached events). 2s grace absorbs minor clock skew.
    start_epoch = dt.datetime.now().astimezone().timestamp() - 2

    w = watch.Watch()
    # resource_version omitted -> start from current; include existing by
    # setting a short timeout loop so the detector keeps running.
    while True:
        try:
            for item in w.stream(core.list_event_for_all_namespaces,
                                 timeout_seconds=0):
                evt = item["object"]
                reason = getattr(evt, "reason", None)
                if reason not in REASONS:
                    continue

                obj = getattr(evt, "involved_object", None)
                ns = (getattr(obj, "namespace", None)
                      or getattr(getattr(evt, "metadata", None), "namespace", "")
                      or "")
                pod = getattr(obj, "name", "") or ""
                msg = getattr(evt, "message", "") or ""
                preemptor = parse_preemptor(msg, resolver)
                ts = event_time(evt)
                ts_epoch = ts.timestamp()
                if ts_epoch < start_epoch:
                    continue  # skip replayed/historical events

                key = (ns, pod)
                first = first_pending.setdefault(key, ts_epoch)
                pending_dur = round(max(0.0, ts_epoch - first), 3)

                with open(csv_path, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([
                        ts.isoformat(), ns, pod, reason, msg,
                        preemptor, pending_dur,
                    ])

                print(f"{ts.strftime('%Y-%m-%d %H:%M:%S'):<23} {reason:<16} "
                      f"{ns:<12} {pod:<28} {pending_dur:>9.3f}  {preemptor}",
                      flush=True)
        except KeyboardInterrupt:
            break
        except Exception as e:  # keep the watcher alive across transient errors
            print(f"[detector] watch reconnecting after: {e}", file=sys.stderr,
                  flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "preemption_log.csv"),
                    help="CSV output path (default: ./preemption_log.csv)")
    ap.add_argument("--context", default=None,
                    help="kube-context to use (default: current context)")
    ap.add_argument("--test", action="store_true",
                    help="connect, print cluster info, and exit")
    args = ap.parse_args()

    def _sigint(_s, _f):
        print("\n[detector] stopped.", flush=True)
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    try:
        if args.test:
            return run_test(args.context)
        return run_watch(args.context, args.csv)
    except Exception as e:
        print(f"[detector] ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

# Detecting and Mitigating Pod Priority Preemption DoS Attacks in Multi-Tenant Kubernetes

A Complex Engineering Project (CEP) on container security. It **reproduces** a real
Kubernetes Denial-of-Service attack that abuses Pod Priority & Preemption, **detects** it
in real time, **mitigates** it with three layers of defense, and **proves** the fix works
with before/after data.

---

## 1. The attack in one paragraph

Kubernetes lets a high-priority pod **preempt** (evict) lower-priority pods when the
cluster is full. In a multi-tenant cluster, a malicious tenant (`bad-tenant`) can create
pods with a very high-priority PriorityClass and request enough CPU to force the scheduler
to **evict other tenants' pods** and keep them stuck `Pending` — a Denial of Service. The
damage comes from reserved CPU **requests** and preemption rights, not from actual CPU load.

---

## 2. Environment

| Component | Value |
|---|---|
| OS | Windows 10, PowerShell |
| Cluster | Minikube profile **`cep`**, 3 nodes, Docker driver, Kubernetes v1.37.0 |
| Python | Run everything with **`py`** (CPython 3.14 — has the `kubernetes` client) |
| Admission control | Kyverno v1.19.2 |
| Metrics | metrics-server addon (`kubectl top`) |

> **Note:** the default `minikube` profile is unused/broken; this project uses profile **`cep`**.
> `kubectl`'s current context is already `cep`.

---

## 3. Prerequisites

- Docker Desktop running
- Minikube + kubectl installed
- Python available as `py`, with the client installed:
  ```powershell
  py -m pip install --user kubernetes
  ```
- **Avast HTTPS scanning must be OFF** while creating the cluster / pulling images.
  Avast's Web Shield MITMs TLS and breaks Minikube, pip, and image registries with
  `x509: certificate signed by unknown authority`. Pause it from the tray icon
  ("Avast shields control → Disable for 1 hour") or disable Web Shield HTTPS scanning.
  Re-enable it when done.

---

## 4. Files

| File | Purpose |
|---|---|
| `detector.py` | Real-time detector — watches the Events API, logs `Preempted`/`FailedScheduling` to `preemption_log.csv`, resolves the preempting pod, tracks pending duration |
| `resourcequota.yml` | **Mitigation 1** — caps `bad-tenant` at 2 CPU / 2Gi requests, 4 CPU / 4Gi limits, 10 pods |
| `nonpreempting-priorityclass.yml` | **Mitigation 2** — `high-priority-nonpreempting` (value 1000000, `preemptionPolicy: Never`) |
| `restrict-priority-class.yml` | **Mitigation 3** — Kyverno `ClusterPolicy` denying preempting priority classes in `bad-tenant` |
| `kube-podpreemption-DoS/` | Attack tooling (cloned): `evict.py`, `estimate-cpu-supply.py`, `priorityClass-high.yml`, `ds/ds-no-pod-priority.yml` |
| `comparison-results.md` | Before/after analysis and results table |
| `01-baseline-before.txt` | Healthy baseline snapshot |
| `02-attack-running.txt` | Attack launch + timestamped victim watch |
| `03-pods-after-attack.txt` | Cluster state during the DoS |
| `04-node-usage-during-attack.txt` | Node CPU/mem during the DoS |
| `05-attack-blocked.txt` | Kyverno admission denial (attack re-run) |
| `06-pods-after-mitigation.txt` | Cluster state after hardening |
| `preemption_log_BEFORE.csv` | Detector log — attack succeeds (3 evictions) |
| `preemption_log_AFTER.csv` | Detector log — attack blocked (empty) |

---

## 5. Build the cluster from scratch (only if not already up)

```powershell
# (Avast HTTPS scanning OFF first)
minikube start -p cep --nodes 3 --driver=docker
minikube addons enable metrics-server -p cep
kubectl get nodes          # 3x Ready
kubectl top nodes          # metrics working

# baseline workloads
kubectl create namespace bad-tenant
kubectl apply -f kube-podpreemption-DoS\priorityClass-high.yml
kubectl apply -f kube-podpreemption-DoS\ds\ds-no-pod-priority.yml
kubectl get pods -A -o wide
```

If an image is slow/stuck pulling inside the cluster (`registry.k8s.io` is slow here),
pull it on the host and side-load it:
```powershell
docker pull <image>
minikube image load <image> -p cep
```

---

## 6. How to run the demo (before vs after)

Use two or three PowerShell windows. Everything runs from the project root:
```powershell
cd C:\Users\shahi\Desktop\IS_CEP
```

**Window 1 — detector (leave running):**
```powershell
py detector.py
```

**Window 2 — live watch:**
```powershell
while ($true) { Clear-Host; "victims $(Get-Date -Format HH:mm:ss)"; kubectl get pods -l run=ds-no-priority -o wide; kubectl get pods -n bad-tenant; Start-Sleep -Milliseconds 500 }
```

**Window 3 — the demo steps:**

```powershell
# 1) Turn mitigations OFF to show the attack working
kubectl delete clusterpolicy restrict-priority-class-bad-tenant
kubectl delete resourcequota bad-tenant-quota -n bad-tenant

# 2) Attack (unprotected) -> 3 victims evicted, 21 attacker pods, DoS
py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7

# 3) Clean up and apply all three mitigations
kubectl -n bad-tenant delete deployment deployment-stuffer --ignore-not-found
kubectl -n bad-tenant delete pod evictor --ignore-not-found
kubectl apply -f resourcequota.yml
kubectl apply -f nonpreempting-priorityclass.yml
kubectl apply -f restrict-priority-class.yml
kubectl get clusterpolicy          # wait: READY = True

# 4) Same attack again (protected) -> blocked by Kyverno at admission
py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7

# 5) Show the results
notepad comparison-results.md
```

---

## 7. Using the detector on its own

```powershell
py detector.py --test        # connect & print cluster info, then exit
py detector.py               # watch forever, append to preemption_log.csv
py detector.py --csv mylog.csv --context cep
```

CSV columns: `timestamp, namespace, evicted_pod_name, reason, message, preempting_pod,
pending_duration_seconds`. The `preempting_pod` is resolved from the event (UID → `ns/name`).

---

## 8. The three mitigations

1. **ResourceQuota** (`resourcequota.yml`) — bounds the blast radius: `bad-tenant` can
   request at most 2 CPU and 10 pods, so large-scale stuffing is impossible.
2. **Non-preempting PriorityClass** (`nonpreempting-priorityclass.yml`) — gives tenants a
   legitimate high-priority option (`high-priority-nonpreempting`) that schedules high but
   **cannot evict** others (`preemptionPolicy: Never`).
3. **Kyverno admission policy** (`restrict-priority-class.yml`) — **primary defense**:
   denies any pod in `bad-tenant` that uses the preempting `high-priority` /
   `attacker-high-priority` class, **at creation time, before scheduling**. Kyverno
   autogen extends the rule to Deployments/ReplicaSets.

Verify:
```powershell
kubectl get resourcequota -n bad-tenant
kubectl get priorityclass
kubectl get clusterpolicy
```

---

## 9. Results

| Metric | BEFORE | AFTER |
|---|---|---|
| Evictions (`Preempted`) | 3 | 0 |
| Victim pods affected | 3 / 3 | 0 / 3 |
| Time to first eviction | ~6 s | never |
| Attacker pods scheduled | 21 | 0 |
| Peak CPU **requests** / node | 88–99% | 16–24% |
| Attack blocked | No | **Yes — at admission** |

Full analysis in `comparison-results.md`.

---

## 10. Troubleshooting

- **`x509: certificate signed by unknown authority`** (kubectl, pip, or image pulls):
  Avast HTTPS scanning is intercepting TLS — turn it off.
- **Image stuck `ImagePullBackOff` / slow:** `registry.k8s.io` is slow here; side-load with
  `docker pull <img>` then `minikube image load <img> -p cep`.
- **`pip install` fails building pydantic/pyyaml:** use `py` (CPython 3.14), not the MSYS2
  `python` — the MSYS2 one lacks prebuilt wheels.
- **Kyverno policy not blocking:** check `kubectl get clusterpolicy` shows `READY = True`.
- **Reset a demo:** delete `deployment-stuffer` and the `evictor` pod from `bad-tenant`;
  the victim DaemonSet recovers automatically.

---

## Notes / honest caveats

- The repo's `evict.py` had an upstream indentation bug (fixed locally).
- The Kyverno policy blocks **both** `high-priority` (the class `evict.py` actually uses)
  and `attacker-high-priority`, so it genuinely blocks the demonstrated attack. The
  non-preempting class `high-priority-nonpreempting` is **not** matched (verified: a
  legitimate pod using it is admitted).
- `kubectl top` shows low CPU **usage** during the attack because the DoS is driven by CPU
  **requests** (reservations), not load — this is expected for this attack class.

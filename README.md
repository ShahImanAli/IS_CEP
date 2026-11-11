# Detecting and Mitigating Pod Priority Preemption DoS Attacks in Multi-Tenant Kubernetes

> **A Complex Engineering Project (CEP) in container & cloud security.**
> This project takes a real, legitimate Kubernetes feature (Pod Priority & Preemption), shows
> how a malicious tenant can **weaponise it into a Denial-of-Service (DoS) attack** against other
> tenants, **detects** that attack in real time, **defends** against it with three independent
> layers, and **proves** the defense works with real before/after measurements.

If you have never seen this project — or Kubernetes — before, **read Section 1 and Section 2
first**. They explain the idea in plain language. Everything after that is detail you can dip into.

---

## Table of contents

1. [What this project is, in plain English](#1-what-this-project-is-in-plain-english)
2. [Key concepts you need (5-minute primer)](#2-key-concepts-you-need-5-minute-primer)
3. [The attack, explained](#3-the-attack-explained)
4. [How the whole system fits together (architecture)](#4-how-the-whole-system-fits-together-architecture)
5. [Repository structure — what every file is](#5-repository-structure--what-every-file-is)
6. [Environment & prerequisites](#6-environment--prerequisites)
7. [Quick start (the easy way: the menu)](#7-quick-start-the-easy-way-the-menu)
8. [Build the cluster from scratch](#8-build-the-cluster-from-scratch)
9. [The detector — implementation](#9-the-detector--implementation)
10. [The three mitigations — implementation](#10-the-three-mitigations--implementation)
11. [Live monitoring with Grafana + Prometheus](#11-live-monitoring-with-grafana--prometheus)
12. [Results — before vs after](#12-results--before-vs-after)
13. [The IEEE report](#13-the-ieee-report)
14. [Troubleshooting](#14-troubleshooting)
15. [Glossary](#15-glossary)
16. [FAQ / honest caveats](#16-faq--honest-caveats)
17. [Where to go next](#17-where-to-go-next)

---

## 1. What this project is, in plain English

A **Kubernetes cluster** is a group of computers ("nodes") that share their CPU and memory to run
applications packaged as **pods**. A **multi-tenant** cluster is one shared by many independent
teams or customers ("tenants"), each isolated in their own **namespace**. The core promise of
multi-tenancy is simple: **one tenant must not be able to harm another.**

Kubernetes has a feature called **Priority & Preemption**. Every pod can be given a *priority
number*. When the cluster is full and an important (high-priority) pod needs to run, the scheduler
is allowed to **preempt** — i.e. forcibly kill — lower-priority pods to make room. This is a useful,
intentional feature: it lets critical workloads win over unimportant ones.

**The vulnerability:** if a tenant is *allowed to give themselves a very high priority*, they can
abuse this. A malicious tenant (here called **`bad-tenant`**) creates many high-priority pods that
**reserve** a lot of CPU. The cluster looks "full" to the scheduler, so it **evicts other tenants'
pods** to make room for the attacker's. The victims' pods are recreated by Kubernetes but can never
find space, so they stay stuck in `Pending` forever. **That is a Denial of Service** — the victim
tenant's application is knocked offline, and it was done entirely from inside a "sandboxed" namespace.

> **An analogy.** Imagine a shared parking garage (the cluster). Normally everyone parks fairly.
> But one company (the attacker) prints itself thousands of "VIP — tow anyone in my way" passes
> (high priority) and *reserves* every space — even though their cars barely move. Security
> (the scheduler) now tows everyone else's cars (preemption) to honour the VIP passes, and those
> cars can never find a spot again (`Pending`). The garage isn't physically full of moving traffic
> — it's full of **reservations**. That distinction is the single most important idea in this project.

**What we built around that idea:**

| Stage | What we did | Deliverable |
|---|---|---|
| **1. Reproduce** | Ran the real attack on a real (local) 3-node cluster | `kube-podpreemption-DoS/evict.py`, snapshot logs `01-…`–`06-…` |
| **2. Detect** | Wrote a real-time detector that logs every eviction and who caused it | `detector.py` → `preemption_log.csv` |
| **3. Mitigate** | Blocked the attack with 3 independent defenses (defense-in-depth) | `restrict-priority-class.yml`, `resourcequota.yml`, `nonpreempting-priorityclass.yml` |
| **4. Prove** | Measured the cluster before and after hardening | `comparison-results.md`, `dashboard.html`, Grafana, IEEE report |

**The headline result:** before defenses, the attack evicted **3 of 3** victim pods in ~6 seconds
and ran 21 attacker pods. After defenses, the identical attack created **0 pods, caused 0 evictions**,
and was rejected the instant it was submitted.

---

## 2. Key concepts you need (5-minute primer)

If these six terms make sense, the rest of the project will too.

- **Node** — a worker machine that provides CPU/RAM and runs pods. In this project each node is a
  **Docker container** on your laptop (because we use `--driver=docker`). We run **3 nodes**:
  `cep` (control-plane) + `cep-m02`, `cep-m03` (workers).
- **Pod** — the smallest thing Kubernetes schedules; it wraps one or more containers. Pods are what
  get placed onto nodes, and pods are what get **preempted** in this attack.
- **Namespace** — a logical partition of the cluster. Each tenant lives in its own namespace
  (`bad-tenant` = attacker). It is the unit of multi-tenant isolation.
- **PriorityClass** — a named priority *number*. Higher = more important. The attacker's class
  `high-priority` has value **9999** and is allowed to preempt. The safe class
  `high-priority-nonpreempting` has value **1,000,000** but is **forbidden** to preempt.
- **Requests vs. Usage — the crux of everything:**
  - **Requests** = the CPU/RAM a pod *reserves* at schedule time. The scheduler places pods by
    **requests**, whether or not the pod actually uses that CPU.
  - **Usage** = the CPU the pod *actually consumes* at runtime.
  - This attack drives CPU **requests** to 88–99% while CPU **usage** stays at ~1–6%. The cluster
    only *looks* full. **The damage comes from reservations + preemption rights, not from load.**
    This is why it's called a *reservation / scheduling DoS*, not a compute-exhaustion DoS.
- **Admission control** — a gate that inspects every object *before* it is created. A
  **validating admission webhook** (we use **Kyverno**) can **reject** a pod at creation time,
  before the scheduler ever sees it. Blocking here is strictly stronger than blocking at
  scheduling time, because the malicious pod never exists.

---

## 3. The attack, explained

### 3.1 The players

| Role | What it is | Defined in |
|---|---|---|
| **Attacker** | An authenticated but **untrusted tenant** confined to the `bad-tenant` namespace. It can create pods and reference PriorityClasses, but has **no** cluster-admin and **cannot** run code on nodes. | — |
| **Attack tool** | `evict.py` — a Python script using the Kubernetes client API. | `kube-podpreemption-DoS/evict.py` |
| **Attacker priority** | `high-priority`, **value 9999**, policy `PreemptLowerPriority` (can evict). | `kube-podpreemption-DoS/priorityClass-high.yml` |
| **Victim** | `ds-no-priority` — a **DaemonSet** (one pod per node, so **3 pods**), with **no** PriorityClass (priority 0). As the lowest-priority workload, it is the first to be evicted. | `kube-podpreemption-DoS/ds/ds-no-pod-priority.yml` |
| **Image (both sides)** | `nginxdemos/hello` — an *idle* web server. It barely uses CPU, which is what proves the attack is about reservations, not load. | — |

### 3.2 The exact command

```powershell
py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7
```

| Flag | Meaning | Value used |
|---|---|---|
| `-n` | target namespace | `bad-tenant` |
| `-r` | number of stuffer replicas | `20` |
| `--cpu` | CPU requested by **each** pod | `1` core |
| `-p` | PriorityClass to use | `high-priority` (value 9999, preempting) |
| `-t` | seconds to wait between the two stages | `7` |

### 3.3 How `evict.py` works, step by step

1. **Stuff.** `create_high_priority_deployment_object()` builds a Deployment named
   **`deployment-stuffer`**: 20 replicas of `nginxdemos/hello`, each requesting **1 CPU + 128Mi**,
   all with `priorityClassName: high-priority`. `create_high_priority_deployment()` submits it.
   These 20 pods fill the cluster's *schedulable* capacity.
2. **Settle.** `time.sleep(7)` — waits so the stuffer pods schedule and saturate the nodes' CPU
   *requests*.
3. **Evict.** `create_evictor_pod_object()` / `create_evictor_pod()` add one more high-priority pod
   named **`evictor`** — the final push that forces preemption of any remaining victim.

So **21 attacker pods = 20 stuffer replicas + 1 evictor.**

### 3.4 What happens to the victims

The cluster's free CPU is now consumed by attacker *requests*. The scheduler **preempts** the
no-priority victim pods (emitting a `Preempted` event on each) to place the 9999-priority pods. The
DaemonSet immediately recreates its victims, but there is no room and nothing lower-priority left to
evict, so each replacement sticks at `Pending` with the scheduler message
*"No preemption victims found … Preemption is not helpful for scheduling."* **That persistent
`Pending` state is the Denial of Service.**

> **Measured reality:** CPU **requests** reached **99% / 88% / 90%** on the three nodes while CPU
> **usage** stayed at **6% / 1% / 1%**. Full on paper, idle in practice — exactly the reservation-DoS
> signature.

---

## 4. How the whole system fits together (architecture)

```
                         ┌─────────────────────────────────────────────┐
                         │        Minikube cluster  (profile: cep)      │
                         │                                              │
  attacker (evict.py) ──▶│  bad-tenant namespace                        │
  "give me 21 pods at    │    deployment-stuffer (20) + evictor (1)     │
   priority 9999"        │             │                                │
                         │             ▼                                │
   ┌────── DEFENSES ─────┤        kube-scheduler ──── preempts ────┐    │
   │ M3 Kyverno (admission, BLOCKS here, before scheduling)        │    │
   │ M1 ResourceQuota  (caps how much bad-tenant can request)      │    │
   │ M2 non-preempt class (high priority but Never evicts)         ▼    │
   │                     │   node cep     node cep-m02   node cep-m03   │
   │                     │  ┌────────┐   ┌────────┐     ┌────────┐      │
   │                     │  │victim 1│   │victim 2│     │victim 3│  ◀── ds-no-priority DaemonSet
   │                     │  └────────┘   └────────┘     └────────┘      │
   └─────────────────────┤                                              │
                         └───────────────┬──────────────────────────────┘
                                         │ (observation path)
             ┌───────────────────────────┼───────────────────────────┐
             ▼                                                         ▼
   detector.py  ── watches Events API ──▶ preemption_log.csv   Prometheus ──▶ Grafana dashboard
   (who evicted whom, exact event log)   (CSV evidence)        (continuous visual: requests,
                                                                pending pods, quota, per node)
```

- **Attack/scheduling path** (solid): attacker → scheduler → preempted victims on the 3 nodes.
- **Defense path**: M3 intercepts at admission (earliest), M1 caps the blast radius, M2 offers a
  safe alternative at scheduling time.
- **Observation path** (two complementary tools): `detector.py` gives the **exact event log**
  ("who evicted whom"); Grafana gives the **continuous visual picture** of cluster state.

---

## 5. Repository structure — what every file is

```
IS_CEP/
├── README.md                          ← you are here (the complete entry point)
├── PROJECT-GUIDE.md                   ← deep study guide (viva-level Q&A, every detail)
├── PROJECT-GUIDE-ROMAN.md             ← the same guide in Roman-Urdu
├── cep-runner.ps1                     ← interactive menu that drives the whole demo
│
├── detector.py                        ← real-time preemption detector (→ preemption_log.csv)
│
├── resourcequota.yml                  ← Mitigation 1: caps bad-tenant's resource requests
├── nonpreempting-priorityclass.yml    ← Mitigation 2: a safe high-priority class that can't evict
├── restrict-priority-class.yml        ← Mitigation 3: Kyverno policy (PRIMARY defense)
│
├── kube-podpreemption-DoS/            ← attack tooling (cloned public research repo)
│   ├── evict.py                       ←   the attack driver (stuff + evict)
│   ├── estimate-cpu-supply.py         ←   helper: estimate cluster CPU supply
│   ├── priorityClass-high.yml         ←   the attacker's "high-priority" (9999) class
│   └── ds/ds-no-pod-priority.yml      ←   the victim DaemonSet (no priority)
│
├── monitoring/                        ← live Grafana + Prometheus layer
│   ├── kube-prometheus-stack-values.yaml   ←   Helm values (trimmed for Minikube)
│   └── cep-dashboard.json             ←   the custom CEP Grafana dashboard
│
├── report/                            ← the IEEE conference paper
│   ├── cep_report.tex                 ←   LaTeX source (compiles on Overleaf)
│   ├── cep_report.pdf                 ←   the built paper
│   └── README.md                      ←   how to build it on Overleaf
│
├── dashboard.html                     ← a standalone static results dashboard (open in a browser)
├── comparison-results.md              ← the full before/after analysis & results tables
│
├── preemption_log.csv                 ← live detector output (overwritten each run)
├── preemption_log_BEFORE.csv          ← captured: attack succeeds (3 Preempted + 11 FailedScheduling)
├── preemption_log_AFTER.csv           ← captured: attack blocked (empty — header only)
│
├── 01-baseline-before.txt             ← evidence snapshots (the "lab notebook"):
├── 02-attack-running.txt              ←   healthy baseline → attack launch → during attack →
├── 03-pods-after-attack.txt           ←   node usage → Kyverno denial → state after hardening
├── 04-node-usage-during-attack.txt
├── 05-attack-blocked.txt
└── 06-pods-after-mitigation.txt
```

---

## 6. Environment & prerequisites

| Component | Value |
|---|---|
| OS | Windows 10, PowerShell |
| Cluster | Minikube profile **`cep`**, 3 nodes, Docker driver, Kubernetes v1.37.0, 8 CPU/node |
| Python | Run everything with **`py`** (CPython 3.14 — it has the `kubernetes` client) |
| Admission control | **Kyverno v1.19.2** |
| Metrics | metrics-server addon (enables `kubectl top`) |
| Monitoring (optional) | kube-prometheus-stack via **Helm** (Prometheus + Grafana) |

**You need, installed and working:**

- **Docker Desktop** — running (Minikube's nodes are Docker containers).
- **Minikube** and **kubectl**.
- **Python as `py`**, with the Kubernetes client:
  ```powershell
  py -m pip install --user kubernetes
  ```
- **Helm** (only for the optional Grafana monitoring): `winget install Helm.Helm`.

> ⚠️ **Avast users, read this.** Avast's Web Shield MITMs TLS and breaks Minikube, `pip`, and image
> registries with `x509: certificate signed by unknown authority`. **Turn Avast HTTPS scanning OFF**
> while creating the cluster / pulling images (tray icon → "Avast shields control → Disable for
> 1 hour"), then re-enable it. Also note: the demo menu is named **`cep-runner.ps1`**, *not*
> `demo.ps1`, because Avast false-positive-quarantines the filename `demo.ps1`.

> **Note on profiles:** this project uses the Minikube profile **`cep`** (the default `minikube`
> profile is unused). `kubectl`'s current context is already set to `cep`.

---

## 7. Quick start (the easy way: the menu)

Everything is driven by an interactive menu, `cep-runner.ps1`. From the project root:

```powershell
cd C:\Users\shahi\Desktop\IS_CEP
powershell -ExecutionPolicy Bypass -File .\cep-runner.ps1
```

You get a menu; **type a letter/number and press Enter.** The recommended full before/after demo is:

> **`S → 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8`**

| Key | Does | Meaning |
|---|---|---|
| **S** | Start the `cep` cluster | Start Minikube (needs Docker + Avast off). Wait for 3× `Ready`. |
| **0** | Preflight check | Verifies context, nodes, the Python client, and which defenses are on. |
| **1** | Start the detector | Opens a window running `py detector.py` — **leave it open** for the whole demo. |
| **2** | Live watch | Opens a window showing victim pods + attacker pods refreshing live. |
| **3** | Mitigations OFF | Deletes the Kyverno policy + ResourceQuota → cluster is now vulnerable. |
| **4** | **Attack** | Runs the attack. Watch 3 victims get `Preempted` / stuck `Pending`. |
| **5** | Show state | Prints victim pods, attacker pods, and node CPU/memory — the damage. |
| **6** | Mitigations ON | Cleans up attacker pods, then applies **all three** defenses. |
| **7** | Attack (blocked) | Re-runs the identical attack → Kyverno **blocks** it → prints a `[BLOCKED]` banner. |
| **8** | Show results | Opens `dashboard.html` + `comparison-results.md`. |

Monitoring and advanced keys (single-mitigation demos, custom attacks, quota editing, node
management, status board, etc.) are documented in detail in **`PROJECT-GUIDE.md` §9 and §14**.

> **Watch out for two look-alike crashes with opposite meanings.** A Python crash saying
> **"already exists" (409)** = a leftover `deployment-stuffer` from a previous run; press **C** to
> clean up, then attack again. A crash saying **"denied the request" / admission webhook** = the
> **Kyverno defense is working** — that's success (option 7).

---

## 8. Build the cluster from scratch

Only needed if the cluster isn't already up. (Avast HTTPS scanning OFF first.)

```powershell
# 1) Create a 3-node cluster and enable metrics
minikube start -p cep --nodes 3 --driver=docker
minikube addons enable metrics-server -p cep
kubectl get nodes          # expect 3× Ready
kubectl top nodes          # metrics working

# 2) Create the attacker namespace and the priority class
kubectl create namespace bad-tenant
kubectl apply -f kube-podpreemption-DoS\priorityClass-high.yml

# 3) Deploy the victim workload (the DaemonSet, one pod per node)
kubectl apply -f kube-podpreemption-DoS\ds\ds-no-pod-priority.yml
kubectl get pods -A -o wide
```

**Why Minikube, and why exactly 3 nodes?** Minikube runs a *real* Kubernetes control plane
(real scheduler, real preemption, real admission webhooks) locally and free, with multi-node
support. Three nodes is the smallest realistic multi-node cluster: the victim DaemonSet puts one
pod on each node, so "**3 of 3 evicted, one per node**" cleanly proves the attack hit *every* node.
(Fewer looks like a toy; more just costs more CPU with no extra teaching value — and actually makes
Mitigation 1 *stronger*, since the 2-CPU cap stays fixed while total capacity grows.)

If an image is slow to pull inside the cluster (`registry.k8s.io` can be slow), side-load it from
the host:

```powershell
docker pull <image>
minikube image load <image> -p cep
```

---

## 9. The detector — implementation

`detector.py` (235 lines, standard `kubernetes` Python client) is a real-time intrusion detector
for this specific attack. It connects to the Kubernetes **Events API** and `watch`es **all
namespaces** for two scheduler event reasons:

- **`Preempted`** — emitted on a **victim** pod that was evicted to make room for a higher-priority pod.
- **`FailedScheduling`** — emitted on a pod that cannot be scheduled (e.g. a recreated victim stuck `Pending`).

Each matching event becomes one row in `preemption_log.csv`:

| Column | Meaning |
|---|---|
| `timestamp` | When the event happened (ISO-8601, local tz) |
| `namespace` | Namespace of the affected pod |
| `evicted_pod_name` | The victim / pending pod named in the event |
| `reason` | `Preempted` or `FailedScheduling` |
| `message` | The raw scheduler message |
| `preempting_pod` | **Who caused it**, parsed as `<ns>/<name>`. The scheduler message sometimes names the preemptor only by **UID** — the `UidResolver` class then looks the UID up via the API and converts it to `namespace/name`. |
| `pending_duration_seconds` | How long that pod has been stuck `Pending`, measured from the first time the detector saw it. |

**Two implementation details worth knowing:**

- **2-second grace window** (`start_epoch`): the watch stream can replay recently-cached events, so
  the detector ignores any event older than 2 seconds before it started. This keeps the BEFORE/AFTER
  logs clean — only preemption *during your demo* is recorded.
- **Self-healing watch loop**: the stream is wrapped so that transient API errors cause a quiet
  reconnect (`[detector] watch reconnecting…`) instead of crashing.

**Run it:**

```powershell
py detector.py --test                 # connect, print cluster info, then exit (health check)
py detector.py                         # watch forever, append to preemption_log.csv
py detector.py --csv mylog.csv --context cep   # custom CSV path / kube-context
```

**The evidence it produced:**

- `preemption_log_BEFORE.csv` — attack succeeding: **3 `Preempted` + 11 `FailedScheduling`**, each
  victim attributed to the exact attacker pod that evicted it.
- `preemption_log_AFTER.csv` — attack blocked: **empty (header only)**.

---

## 10. The three mitigations — implementation

This is **defense-in-depth**: three independent controls, each stopping the attack at a different
stage. A one-line mental model: **M3 = the lock on the door (primary). M1 = a cap if anything slips
through (backstop). M2 = the legitimate key tenants should use instead.**

### Mitigation 3 — Kyverno admission policy (PRIMARY) · `restrict-priority-class.yml`

The strongest defense, and the one that actually stops the demonstrated attack. Kyverno is a
validating admission controller; this `ClusterPolicy` **rejects, at creation time**, any pod in
`bad-tenant` whose `priorityClassName` is a preempting class.

```yaml
spec:
  validationFailureAction: Enforce        # actually blocks (vs Audit = log only)
  background: true
  rules:
    - name: block-high-priority-in-bad-tenant
      match: { any: [ { resources: { kinds: [Pod], namespaces: [bad-tenant] } } ] }
      validate:
        message: "Pods in 'bad-tenant' may not use a preempting high-priority
                  PriorityClass. Use 'high-priority-nonpreempting' instead."
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.priorityClassName || '' }}"
                operator: AnyIn
                value: ["high-priority", "attacker-high-priority"]
```

When `evict.py` calls `create_namespaced_deployment`, Kyverno returns **HTTP 400 — "admission
webhook `validate.kyverno.svc-fail` denied the request … policy restrict-priority-class-bad-tenant"**;
the script crashes on its **first** API call → **0 pods created**. Two key points:
- **Kyverno autogen** automatically extends the Pod rule to **Deployments and ReplicaSets**, so
  blocking Pods also blocks the Deployment the attacker actually submits.
- **Admission-time blocking is strictly stronger than scheduling-time blocking:** the malicious pod
  never exists, so there is no preemption, no `Pending` victims, and no scheduler churn.

### Mitigation 1 — ResourceQuota (blast-radius cap) · `resourcequota.yml`

Bounds what `bad-tenant` can *ever* request, so even if a preempting pod slipped through, the attack
can't scale.

| Key | Value | Effect |
|---|---|---|
| `requests.cpu` | **2** | at most 2 CPU reserved total → only ~2 attacker pods (each wants 1 CPU) |
| `requests.memory` | **2Gi** | at most 2Gi reserved |
| `limits.cpu` / `limits.memory` | **4** / **4Gi** | hard limits |
| `pods` | **10** | at most 10 pods in the namespace |

A `-r 20` attack (21 pods) is cut to ~2 — a **90.5% reduction**. The math: `N_max = min(⌊2/c⌋, 10)`
where `c` is per-pod CPU. For `c = 1`, the CPU cap binds (→ 2); for a tiny `c = 0.1`, the 10-pod cap binds.

### Mitigation 2 — Non-preempting PriorityClass (safe alternative) · `nonpreempting-priorityclass.yml`

Gives tenants a legitimate way to be high-priority **without** eviction rights.

```yaml
kind: PriorityClass
metadata: { name: high-priority-nonpreempting }
value: 1000000              # even HIGHER than the attacker's 9999 …
preemptionPolicy: Never     # … but can NEVER evict anyone  ← the magic line
globalDefault: false
```

The value (1,000,000 > 9999) is deliberate: it proves **high priority itself is harmless — the
danger is the *preemption right*, not the number.** A pod using this class schedules when there's
room and *waits* (never kills neighbours) when there isn't. It is **not** matched by the Kyverno
policy, so a legitimate pod using it is admitted (verified).

**Verify all three:**

```powershell
kubectl get resourcequota -n bad-tenant     # M1
kubectl get priorityclass                   # M2 (and the attacker's class)
kubectl get clusterpolicy                   # M3 — wait for READY = True
```

---

## 11. Live monitoring with Grafana + Prometheus

Optional but recommended: a Grafana + Prometheus layer that visualises the attack and the defenses
on live time-series graphs, not just in CSV/text. It uses the standard **kube-prometheus-stack**
(Prometheus + kube-state-metrics + node-exporter + Grafana) plus a custom dashboard tailored to this
attack (`monitoring/cep-dashboard.json`, uid `cep-preempt-dos`).

**Easiest path — from `cep-runner.ps1`:**

- **G** — set up Grafana + Prometheus (one time; needs Helm; first run pulls images, 3–6 min).
- **V** — open the dashboard (port-forward + browser). **Login: `admin` / `cep-admin`.**
- **GX** — remove the monitoring stack.

**Manual equivalent:**

```powershell
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --install cep-mon prometheus-community/kube-prometheus-stack `
  -n monitoring --create-namespace -f monitoring\kube-prometheus-stack-values.yaml
kubectl -n monitoring rollout status deploy/cep-mon-grafana --timeout=240s
kubectl create configmap cep-grafana-dashboard -n monitoring `
  --from-file=monitoring\cep-dashboard.json --dry-run=client -o yaml | kubectl apply -f -
kubectl label configmap cep-grafana-dashboard -n monitoring grafana_dashboard=1 --overwrite
kubectl -n monitoring port-forward svc/cep-mon-grafana 3000:80   # open http://localhost:3000
```

**What the dashboard shows** (the whole before/after story live): the signature **CPU requests vs.
usage vs. capacity** panel (requests climb to capacity while usage stays flat → reservation DoS),
**pending pods by namespace** (victims), **running pods by namespace** (attacker flood → 21, capped
to ~2 by the quota, 0 with Kyverno), **per-node CPU-request saturation**, and the **bad-tenant
ResourceQuota used-vs-hard** cap.

> **Honest limitation:** preemption *events* (`Preempted` / `FailedScheduling`) are not a native
> Prometheus metric, so Grafana shows the **effects** (pending pods, CPU saturation, pod counts)
> while `detector.py` captures the **exact events** (who evicted whom). The two are complementary by
> design. Full panel list and PromQL are in **`PROJECT-GUIDE.md` §11**.

---

## 12. Results — before vs after

The identical attack command was run twice: once with defenses off, once with all three applied.

| Metric | BEFORE (no defense) | AFTER (hardened) |
|---|---|---|
| Attack outcome | ✅ Succeeded — tenant DoS achieved | ❌ Blocked |
| Where it was stopped | Not stopped at all | **Admission** (Kyverno), *before scheduling* |
| Evictions (`Preempted`) | **3** | **0** |
| Victim pods affected | 3 of 3 (100%) | 0 of 3 |
| Time to first eviction | **≈ 6 s** | never |
| Attacker pods scheduled | **21** (20 stuffer + 1 evictor) | **0** (Deployment *and* Pod rejected) |
| `FailedScheduling` events | 11 | 0 |
| Peak CPU **requests** / node | cep 99%, m02 88%, m03 90% | 24% / 17% / 16% |
| Peak CPU **usage** | 6% / 1% / 1% | 6% / 1% / 1% (proves it's reservation-based) |
| Detector log | `preemption_log_BEFORE.csv` (3 + 11 rows) | `preemption_log_AFTER.csv` (empty) |

**Attribution captured by the detector** (BEFORE run): each victim mapped to the exact attacker pod
that evicted it — e.g. `ds-no-priority-hdsng` on `cep` ← `bad-tenant/deployment-stuffer-…-plc5c`;
`ds-no-priority-mr6np` on `cep-m02` ← `bad-tenant/evictor`.

Full analysis, tables and the verbatim Kyverno denial are in **`comparison-results.md`**; a static
visual summary is in **`dashboard.html`**.

---

## 13. The IEEE report

`report/cep_report.tex` → `report/cep_report.pdf` is a complete **IEEE conference-format** paper
(IEEEtran), test-compiled with no errors. Its thesis in one sentence: *a malicious tenant abuses
Kubernetes priority/preemption to evict other tenants (a DoS); a three-layer defense —
ResourceQuota, non-preempting PriorityClass, Kyverno admission policy — stops it, and admission-time
blocking is the strongest control.*

- All figures are drawn **natively in LaTeX from the real measured data** (no screenshots needed):
  per-node CPU requests vs. usage; before/after counts; the verbatim Kyverno HTTP 400 denial; and
  the defense-in-depth control-flow diagram.
- To build it: upload the `report/` folder to **Overleaf**, set compiler to **pdfLaTeX**, recompile.
  See `report/README.md`. Before submitting, fill in your name/university/email in the `\author{}` block.

A full, section-by-section, figure-by-figure, reference-by-reference walkthrough of the report (for
defending it in a viva) is in **`PROJECT-GUIDE.md` §12**.

---

## 14. Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `x509: certificate signed by unknown authority` (kubectl, pip, image pulls) | Avast HTTPS scanning is intercepting TLS — **turn it off**, retry. |
| Image stuck `ImagePullBackOff` / very slow | `registry.k8s.io` is slow here — side-load: `docker pull <img>` then `minikube image load <img> -p cep`. |
| `pip install` fails building pydantic/pyyaml | Use **`py`** (CPython 3.14), not the MSYS2 `python` — the MSYS2 one lacks prebuilt wheels. |
| Attack throws Python **"already exists" (409)** | Leftover `deployment-stuffer` from a previous run — press **C** (cleanup), then re-attack. |
| Attack throws **"denied the request" / admission webhook** | **Not an error — this is success.** Kyverno is blocking the attack (option 7). |
| Kyverno policy not blocking | Check `kubectl get clusterpolicy` shows **`READY = True`**. |
| Victims stuck `Pending` after a test | Clean up attacker pods (menu **C**/**9**); the victim DaemonSet self-recovers once CPU is freed. |
| Grafana won't open | Ensure Helm is installed and the stack is up (menu **G**); leave the port-forward window (menu **V**) open; login `admin` / `cep-admin`. |

---

## 15. Glossary

- **Preemption** — the scheduler forcibly evicting lower-priority pods to make room for a
  higher-priority one when the cluster is full.
- **Eviction** — a pod being killed as a result of preemption (shows a `Preempted` event).
- **Pending** — a pod that can't be scheduled (no room). Persistent `Pending` of victims = the DoS.
- **DaemonSet** — a controller that runs exactly one copy of a pod on every node (and recreates it
  if it dies). The victim here is a DaemonSet, which is why it gives "one clean victim per node" and
  why it keeps producing `Pending` replacements during the attack.
- **Cleanup vs. mitigation** — *cleanup* (deleting attacker pods) is **recovery**: it frees CPU so
  `Pending` victims reschedule to `Running`. *Mitigation* (the 3 defenses) is **prevention**: it
  stops the attack from being *recreated*. Menu option 6 does cleanup first (victims recover), then
  applies the defenses (so it can't happen again).
- **Admission webhook** — a gate (Kyverno here) that validates/rejects objects before they are created.
- **ResourceQuota** — a per-namespace cap on total requests/limits/pod count.

---

## 16. FAQ / honest caveats

- **"Isn't this just a CPU flood?"** No. It's a **reservation / scheduling DoS**. Live CPU *usage*
  stays ~1–6%; the harm comes from CPU *requests* (88–99%) + preemption rights.
- **"Which defense actually stops it?"** M3 (Kyverno) blocks it at admission — the primary control.
  M1 is a backstop cap; M2 is the safe alternative. Together = defense-in-depth.
- **"Why block at admission instead of scheduling?"** Strictly stronger — the malicious pod never
  exists, so there's nothing to preempt with.
- **"How do you know it worked?"** `preemption_log_BEFORE.csv` = 3 Preempted + 11 FailedScheduling;
  `preemption_log_AFTER.csv` = empty. Plus the `01-…`–`06-…` snapshots, the dashboards, and the report.
- **"Why is the safe class's value (1,000,000) *higher* than the attacker's (9999)?"** To prove high
  priority is fine — the danger is the *preemption policy*, not the number.
- **Caveats (nothing is fabricated):** the upstream `evict.py` had an indentation bug, **fixed
  locally**. The Kyverno policy blocks **both** `high-priority` (the class the attack uses) and
  `attacker-high-priority`, and does **not** match the safe `high-priority-nonpreempting`. `kubectl
  top` showing low CPU usage during the attack is **expected** for this attack class.

---

## 17. Where to go next

- **`PROJECT-GUIDE.md`** — the exhaustive study/defense guide: every menu key's real command, every
  default, every report figure/table/reference, likely examiner questions with answers, and the
  "key concepts explained simply" primer. Start here if you need viva-level depth.
- **`PROJECT-GUIDE-ROMAN.md`** — the same guide in Roman-Urdu.
- **`comparison-results.md`** — the full numeric before/after analysis.
- **`report/cep_report.pdf`** — the formal IEEE write-up.

---

*This project is for authorized, educational security research. The attack is run only against a
local, self-owned Minikube cluster — never against infrastructure you do not own or have explicit
permission to test.*

# demo.ps1 - Interactive runner for the Pod Priority Preemption DoS CEP.
# Run from the project root:   powershell -ExecutionPolicy Bypass -File .\demo.ps1
# Just press a number. No need to remember any kubectl/py commands.

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root

# ---------- pretty helpers ----------
function Title($t) {
    Write-Host ""
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
}
function Step($t)  { Write-Host "`n>> $t" -ForegroundColor Yellow }
function Run($cmd) {
    Write-Host "   $cmd" -ForegroundColor DarkGray
    Invoke-Expression $cmd
}
function Pause-Key { Write-Host "`n(press any key to return to the menu)" -ForegroundColor DarkGray; [void]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
function Confirm($msg) {
    Write-Host "$msg [y/N] " -ForegroundColor Magenta -NoNewline
    return ((Read-Host) -match '^(y|Y)')
}

# ---------- actions ----------
function Start-Cluster {
    Title "S. Start the Minikube cluster"
    Step "checking current status"
    $status = (minikube status -p cep 2>&1 | Out-String)
    if ($status -match "host: Running" -and $status -match "apiserver: Running") {
        Write-Host "`nCluster is already running." -ForegroundColor Green
        Run "kubectl get nodes"
        Pause-Key; return
    }
    Write-Host "`nCluster is not running. Starting it now (this takes 1-3 minutes)..." -ForegroundColor Yellow
    Run "minikube start -p cep"
    Step "verifying nodes"
    Run "kubectl get nodes"
    Write-Host "`nIf all 3 nodes are Ready, you're good to go. Run 0 (Preflight) next." -ForegroundColor Green
    Pause-Key
}

function Preflight {
    Title "0. Preflight - is everything ready?"
    Step "kubectl context (should be 'cep')"
    Run "kubectl config current-context"
    Step "cluster nodes (want 3x Ready)"
    Run "kubectl get nodes"
    Step "detector dependencies + cluster access"
    Run "py detector.py --test"
    Step "current defenses in place?"
    Run "kubectl get clusterpolicy,resourcequota -n bad-tenant 2>`$null"
    Pause-Key
}

function Start-Detector {
    Title "1. Start the live detector (opens a new window)"
    Write-Host "A new PowerShell window will open and watch the cluster for preemption." -ForegroundColor Gray
    Write-Host "Leave it open during the whole demo. Logs go to preemption_log.csv." -ForegroundColor Gray
    Start-Process powershell -ArgumentList "-NoExit","-Command","Set-Location '$Root'; Write-Host 'DETECTOR - leave this open' -ForegroundColor Cyan; py detector.py"
    Write-Host "`nDetector window launched." -ForegroundColor Green
    Pause-Key
}

function Start-Watch {
    Title "2. Start the live victim watch (opens a new window)"
    Write-Host "Shows victim pods (top) and attacker pods (bottom), refreshing continuously." -ForegroundColor Gray
    $w = "Set-Location '$Root'; while (`$true) { Clear-Host; 'VICTIMS  ' + (Get-Date -Format HH:mm:ss); kubectl get pods -l run=ds-no-priority -o wide; Write-Host ''; 'ATTACKER (bad-tenant)'; kubectl get pods -n bad-tenant; Start-Sleep -Milliseconds 700 }"
    Start-Process powershell -ArgumentList "-NoExit","-Command",$w
    Write-Host "`nWatch window launched." -ForegroundColor Green
    Pause-Key
}

function Mitigations-Off {
    Title "3. Turn the defenses OFF (so the attack can succeed)"
    if (-not (Confirm "This removes the Kyverno policy and the quota. Continue?")) { return }
    Step "delete Kyverno admission policy"
    Run "kubectl delete clusterpolicy restrict-priority-class-bad-tenant --ignore-not-found"
    Step "delete the resource quota"
    Run "kubectl delete resourcequota bad-tenant-quota -n bad-tenant --ignore-not-found"
    Write-Host "`nDefenses are now OFF. The cluster is vulnerable." -ForegroundColor Red
    Pause-Key
}

function Attack {
    Title "4. Launch the attack (bad-tenant floods high-priority pods)"
    $pol = (kubectl get clusterpolicy restrict-priority-class-bad-tenant 2>&1 | Out-String)
    if ($pol -notmatch "NotFound" -and $pol -match "restrict-priority-class") {
        Write-Host "`n  [!] WARNING: defenses look like they are still ON." -ForegroundColor Yellow
        Write-Host "      The attack will be BLOCKED. Press 3 first to show it succeeding." -ForegroundColor Yellow
        if (-not (Confirm "Continue anyway?")) { return }
    }
    Write-Host "This creates high-priority pods that reserve CPU and EVICT other tenants' pods." -ForegroundColor Gray
    if (-not (Confirm "Launch the attack now?")) { return }
    Step "run the evictor"
    Run "py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7"
    Write-Host "`nWatch the detector + watch windows: victims should get Preempted / stuck Pending." -ForegroundColor Yellow
    Pause-Key
}

function Show-State {
    Title "5. Show the cluster state right now"
    Step "victim pods"
    Run "kubectl get pods -l run=ds-no-priority -o wide"
    Step "attacker pods"
    Run "kubectl get pods -n bad-tenant -o wide"
    Step "node CPU/memory requests"
    Run "kubectl describe nodes | Select-String -Pattern 'Name:|cpu ','memory ' "
    Pause-Key
}

function Mitigations-On {
    Title "6. Clean up and apply ALL THREE defenses"
    Step "remove attacker workloads"
    Run "kubectl -n bad-tenant delete deployment deployment-stuffer --ignore-not-found"
    Run "kubectl -n bad-tenant delete pod evictor --ignore-not-found"
    Step "Mitigation 1 - ResourceQuota (caps bad-tenant CPU/pods)"
    Run "kubectl apply -f resourcequota.yml"
    Step "Mitigation 2 - Non-preempting PriorityClass (high but cannot evict)"
    Run "kubectl apply -f nonpreempting-priorityclass.yml"
    Step "Mitigation 3 - Kyverno policy (blocks the attack at admission)"
    Run "kubectl apply -f restrict-priority-class.yml"
    Step "wait for the policy to be READY = True"
    Run "kubectl get clusterpolicy"
    Write-Host "`nDefenses are now ON." -ForegroundColor Green
    Pause-Key
}

function Attack-Blocked {
    Title "7. Run the SAME attack again (now protected)"
    Write-Host "Kyverno should REJECT the attacker pods at creation time - before scheduling." -ForegroundColor Gray
    if (-not (Confirm "Re-run the attack?")) { return }
    Step "running the same attack command (output captured)"
    Write-Host "   py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7" -ForegroundColor DarkGray
    $raw = (& py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7 2>&1 | Out-String)

    $reason = $null
    if ($raw -match "Pods in the '[^']*'[^""\\]*") { $reason = $matches[0] }
    $blocked = $raw -match "denied the request"

    Write-Host ""
    if ($blocked) {
        Write-Host (" " + ("-"*60)) -ForegroundColor Green
        Write-Host "  [BLOCKED] Kyverno DENIED the attack at admission." -ForegroundColor Green
        Write-Host (" " + ("-"*60)) -ForegroundColor Green
        if ($reason) { Write-Host "`n  Policy said:" -ForegroundColor Green; Write-Host "    $reason" -ForegroundColor White }
        Write-Host "`n  The attacker's pods were NEVER created. (The Python error you'd" -ForegroundColor Gray
        Write-Host "  normally see is just the attacker's script crashing because the" -ForegroundColor Gray
        Write-Host "  cluster refused it - that crash IS the defense working.)" -ForegroundColor Gray
    } else {
        Write-Host "  [!] No denial detected - are the defenses applied? Run 6 first." -ForegroundColor Yellow
    }

    Step "proof: attacker namespace is still empty"
    Run "kubectl get pods -n bad-tenant"
    Step "proof: victim pods are still Running"
    Run "kubectl get pods -l run=ds-no-priority -o wide"
    Pause-Key
}

function Show-Results {
    Title "8. Show the results"
    $dash = Join-Path $Root "dashboard.html"
    if (Test-Path $dash) { Step "opening the visual dashboard"; Start-Process $dash }
    if (Test-Path (Join-Path $Root "comparison-results.md")) { Step "opening the written comparison"; Start-Process notepad.exe "comparison-results.md" }
    Pause-Key
}

function Show-Specs {
    Title "I. Inspect the specs (read-only - attack + defenses)"

    Step "PriorityClasses - the ATTACK class vs the SAFE class"
    Run "kubectl get priorityclass high-priority high-priority-nonpreempting -o custom-columns=NAME:.metadata.name,VALUE:.value,PREEMPTION:.preemptionPolicy"
    Write-Host "   high-priority (9999, PreemptLowerPriority) = can evict  |  high-priority-nonpreempting (1000000, Never) = cannot evict" -ForegroundColor DarkGray

    Step "ResourceQuota caps for bad-tenant (Mitigation 1)"
    $q = (kubectl get resourcequota bad-tenant-quota -n bad-tenant 2>&1 | Out-String)
    if ($q -match "bad-tenant-quota") {
        Run "kubectl describe resourcequota bad-tenant-quota -n bad-tenant"
    } else {
        Write-Host "   (quota not applied right now - showing the defaults from resourcequota.yml)" -ForegroundColor DarkGray
        Run "Get-Content resourcequota.yml"
    }

    Step "Attack specs (the command and per-pod resources)"
    Write-Host "   Command: py kube-podpreemption-DoS\evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7" -ForegroundColor White
    Write-Host "     -r 20            = 20 stuffer pods (+1 evictor = 21 total)" -ForegroundColor Gray
    Write-Host "     --cpu 1          = each pod reserves 1 CPU core" -ForegroundColor Gray
    Write-Host "     -p high-priority = preempting class (value 9999)" -ForegroundColor Gray
    Write-Host "     -t 7             = wait 7s before the final evictor pod" -ForegroundColor Gray
    Write-Host "     image nginxdemos/hello  |  requests/limits: cpu=1, memory=128Mi per pod" -ForegroundColor Gray

    Step "attacker pods live right now (shows priority 9999 when an attack is running)"
    Run "kubectl get pods -n bad-tenant -o custom-columns=NAME:.metadata.name,PRIORITY:.spec.priority,CLASS:.spec.priorityClassName,NODE:.spec.nodeName"

    Step "the normal victim pods (priority 0, no class)"
    Run "kubectl get pods -l run=ds-no-priority -o custom-columns=NAME:.metadata.name,PRIORITY:.spec.priority,CLASS:.spec.priorityClassName,NODE:.spec.nodeName"
    Pause-Key
}

function Defense-Status {
    Title "T. Defense status board - what is applied right now?"

    function Show-Flag($label, $present) {
        if ($present) { Write-Host ("  [ON ]  " + $label) -ForegroundColor Green }
        else          { Write-Host ("  [OFF]  " + $label) -ForegroundColor Red }
    }

    $quota = (kubectl get resourcequota bad-tenant-quota -n bad-tenant 2>&1 | Out-String)
    $class = (kubectl get priorityclass high-priority-nonpreempting 2>&1 | Out-String)
    $pol   = (kubectl get clusterpolicy restrict-priority-class-bad-tenant 2>&1 | Out-String)
    $pods  = (kubectl get pods -n bad-tenant --no-headers 2>&1 | Out-String)

    $quotaOn = ($quota -match "bad-tenant-quota")
    $classOn = ($class -match "high-priority-nonpreempting")
    $polOn   = ($pol   -match "restrict-priority-class-bad-tenant")
    $attackLive = ($pods -match "deployment-stuffer" -or $pods -match "evictor")

    Write-Host "`n  MITIGATIONS" -ForegroundColor Cyan
    Show-Flag "M1  ResourceQuota (caps bad-tenant to 2 CPU / 10 pods)" $quotaOn
    Show-Flag "M2  Non-preempting PriorityClass (safe high priority)" $classOn
    Show-Flag "M3  Kyverno admission policy (blocks the attack)      " $polOn

    Write-Host "`n  ATTACK" -ForegroundColor Cyan
    if ($attackLive) { Write-Host "  [!!!]  Attacker pods are PRESENT in bad-tenant" -ForegroundColor Red }
    else             { Write-Host "  [ -- ]  No attacker pods (bad-tenant is clean)" -ForegroundColor Green }

    Write-Host "`n  SUMMARY" -ForegroundColor Cyan
    if ($quotaOn -and $classOn -and $polOn) {
        Write-Host "  Fully defended (all 3 mitigations ON)." -ForegroundColor Green
    } elseif (-not $quotaOn -and -not $classOn -and -not $polOn) {
        Write-Host "  UNDEFENDED - the attack will succeed. (Press 6 to defend.)" -ForegroundColor Red
    } else {
        Write-Host "  Partially defended - only some mitigations are ON (isolated-demo mode)." -ForegroundColor Yellow
    }

    if ($quotaOn) {
        Write-Host "`n  Quota usage (USED / HARD):" -ForegroundColor Gray
        Run "kubectl get resourcequota bad-tenant-quota -n bad-tenant"
    }
    Pause-Key
}

function View-Detector-Log {
    Title "L. View the detector log (preemption_log.csv)"
    $csv = Join-Path $Root "preemption_log.csv"
    if (-not (Test-Path $csv)) {
        Write-Host "`n  No preemption_log.csv yet. Start the detector (option 1) and run an attack first." -ForegroundColor Yellow
        Pause-Key; return
    }

    $rows = @(Import-Csv $csv)
    $preempted = @($rows | Where-Object { $_.reason -eq "Preempted" })
    $failed    = @($rows | Where-Object { $_.reason -eq "FailedScheduling" })

    Write-Host "`n  Summary:" -ForegroundColor Cyan
    Write-Host ("    Total events logged : {0}" -f $rows.Count)
    Write-Host ("    Preempted (evictions): {0}" -f $preempted.Count) -ForegroundColor $(if ($preempted.Count) { "Red" } else { "Green" })
    Write-Host ("    FailedScheduling     : {0}" -f $failed.Count)

    if ($preempted.Count) {
        Write-Host "`n  Evictions (victim  ->  preempting attacker pod):" -ForegroundColor Cyan
        $preempted | ForEach-Object {
            Write-Host ("    {0,-26} <- {1}" -f $_.evicted_pod_name, $_.preempting_pod) -ForegroundColor White
        }
    } else {
        Write-Host "`n  No evictions recorded - the cluster was never successfully attacked" -ForegroundColor Green
        Write-Host "  (empty log = mitigations held, or no attack has run yet)." -ForegroundColor Green
    }

    if (Confirm "`nOpen the full CSV in your spreadsheet / editor?") { Start-Process $csv }
    Pause-Key
}

function Reset-Demo {
    Title "9. Reset the demo (back to a clean baseline)"
    if (-not (Confirm "Remove attacker workloads and re-apply defenses?")) { return }
    Run "kubectl -n bad-tenant delete deployment deployment-stuffer --ignore-not-found"
    Run "kubectl -n bad-tenant delete pod evictor --ignore-not-found"
    Run "kubectl apply -f resourcequota.yml"
    Run "kubectl apply -f nonpreempting-priorityclass.yml"
    Run "kubectl apply -f restrict-priority-class.yml"
    Write-Host "`nReset complete. Victim DaemonSet recovers automatically." -ForegroundColor Green
    Pause-Key
}

# ---------- ADVANCED: step-wise mitigations ----------
function Clear-All-Mitigations {
    Title "M0. Remove ALL mitigations (clean slate)"
    Step "removing Kyverno policy, quota, and the non-preempting class"
    Run "kubectl delete clusterpolicy restrict-priority-class-bad-tenant --ignore-not-found"
    Run "kubectl delete resourcequota bad-tenant-quota -n bad-tenant --ignore-not-found"
    Run "kubectl delete priorityclass high-priority-nonpreempting --ignore-not-found"
    Write-Host "`nAll mitigations removed. Cluster is fully undefended." -ForegroundColor Red
    Pause-Key
}

function Cleanup-Attack {
    Title "C. Clean up attacker pods only (reset to a clean baseline)"
    Write-Host "Removes the attacker's leftover pods from a previous run so the next test" -ForegroundColor Gray
    Write-Host "starts fresh. This touches NO defenses - mitigations stay exactly as they are." -ForegroundColor Gray
    Step "deleting attacker workloads in bad-tenant"
    Run "kubectl -n bad-tenant delete deployment deployment-stuffer --ignore-not-found"
    Run "kubectl -n bad-tenant delete pod evictor --ignore-not-found"
    Step "attacker namespace should now be empty"
    Run "kubectl get pods -n bad-tenant"
    Step "victim pods (the DaemonSet recovers automatically)"
    Run "kubectl get pods -l run=ds-no-priority -o wide"
    Write-Host "`nClean baseline ready. Now apply a mitigation (M1/M2/M3) then attack (4)." -ForegroundColor Green
    Pause-Key
}

function Apply-M1 {
    Title "M1. Apply ONLY Mitigation 1 - ResourceQuota"
    Write-Host "Caps bad-tenant at 2 CPU / 2Gi requests and 10 pods. It does NOT stop" -ForegroundColor Gray
    Write-Host "preemption - it LIMITS it. With -r 20 the attacker will only get ~2 pods." -ForegroundColor Gray
    Run "kubectl apply -f resourcequota.yml"
    Step "the quota now in force"
    Run "kubectl get resourcequota -n bad-tenant"
    Write-Host "`nNow run the attack (option 4) and watch: only ~2 attacker pods are created," -ForegroundColor Green
    Write-Host "not 21. The blast radius is capped." -ForegroundColor Green
    Pause-Key
}

function Apply-M2 {
    Title "M2. Apply ONLY Mitigation 2 - Non-preempting PriorityClass"
    Write-Host "This class is HIGH priority (value 1000000) but preemptionPolicy: Never," -ForegroundColor Gray
    Write-Host "so a pod using it schedules high yet CANNOT evict anyone. It is the safe" -ForegroundColor Gray
    Write-Host "alternative tenants should use. (By itself it does NOT block the normal" -ForegroundColor Gray
    Write-Host "'high-priority' attack - that is M3's job.)" -ForegroundColor Gray
    Run "kubectl apply -f nonpreempting-priorityclass.yml"
    Step "compare the two classes (look at PREEMPTIONPOLICY)"
    Run "kubectl get priorityclass high-priority high-priority-nonpreempting"
    if (Confirm "`nDemo it? Run the attacker USING the non-preempting class (should evict NOBODY)") {
        Step "attacker tries with the non-preempting class"
        Run "py kube-podpreemption-DoS\evict.py -n bad-tenant -r 5 --cpu 1 -p high-priority-nonpreempting -t 7"
        Step "victims should still be Running (0 evictions)"
        Run "kubectl get pods -l run=ds-no-priority -o wide"
        Write-Host "`nPoint: same high priority, but NO eviction - because preemption is disabled." -ForegroundColor Green
    }
    Pause-Key
}

function Apply-M3 {
    Title "M3. Apply ONLY Mitigation 3 - Kyverno admission policy"
    Write-Host "The primary defense: rejects any pod in bad-tenant using the preempting" -ForegroundColor Gray
    Write-Host "'high-priority' class AT CREATION, before the scheduler ever sees it." -ForegroundColor Gray
    Run "kubectl apply -f restrict-priority-class.yml"
    Step "wait for READY = True"
    Run "kubectl get clusterpolicy"
    Write-Host "`nNow run the attack (option 4): 0 pods created, blocked at admission." -ForegroundColor Green
    Pause-Key
}

function Custom-Attack {
    Title "X. Custom attack - choose the size yourself"
    $r = Read-Host "  how many attacker pods (replicas)? [default 20]"; if (-not $r) { $r = 20 }
    $c = Read-Host "  CPU per pod? [default 1]"; if (-not $c) { $c = 1 }
    $p = Read-Host "  priority class? [default high-priority]"; if (-not $p) { $p = "high-priority" }
    Write-Host "`nLaunching: $r pods x $c CPU each, class '$p'." -ForegroundColor Yellow
    if (-not (Confirm "Go?")) { return }
    Run "py kube-podpreemption-DoS\evict.py -n bad-tenant -r $r --cpu $c -p $p -t 7"
    Write-Host "`nTip: more pods / more CPU = harder hit. The ResourceQuota (M1) caps this" -ForegroundColor Gray
    Write-Host "no matter how big -r is, so M1 stays effective even against a huge attack." -ForegroundColor Gray
    Pause-Key
}

function Node-Manage {
    Title "N. Cluster nodes - view or add"
    Step "current nodes"
    Run "kubectl get nodes"
    Run "minikube node list -p cep"
    Write-Host "`nMore nodes = more total CPU, so the attacker needs MORE pods to fill the" -ForegroundColor Gray
    Write-Host "cluster. The ResourceQuota (2 CPU cap) becomes even more effective." -ForegroundColor Gray
    if (Confirm "`nAdd one more worker node now? (takes 1-2 minutes)") {
        Run "minikube node add -p cep"
        Step "nodes after adding"
        Run "kubectl get nodes"
    }
    Pause-Key
}

function Edit-Quota {
    Title "E. Set the bad-tenant resource caps yourself"
    Step "current caps (USED / HARD limit)"
    Run "kubectl describe resourcequota bad-tenant-quota -n bad-tenant"
    Write-Host "`nEnter new values, or press Enter to keep the default shown in [ ]." -ForegroundColor Gray
    $rc = Read-Host "  requests.cpu  (cores)  [2]";   if (-not $rc) { $rc = "2" }
    $rm = Read-Host "  requests.memory        [2Gi]"; if (-not $rm) { $rm = "2Gi" }
    $lc = Read-Host "  limits.cpu    (cores)  [4]";   if (-not $lc) { $lc = "4" }
    $lm = Read-Host "  limits.memory          [4Gi]"; if (-not $lm) { $lm = "4Gi" }
    $pd = Read-Host "  max pods               [10]";  if (-not $pd) { $pd = "10" }

    $yaml = @"
apiVersion: v1
kind: ResourceQuota
metadata:
  name: bad-tenant-quota
  namespace: bad-tenant
spec:
  hard:
    requests.cpu: "$rc"
    requests.memory: $rm
    limits.cpu: "$lc"
    limits.memory: $lm
    pods: "$pd"
"@
    Write-Host "`nApplying:" -ForegroundColor Yellow
    Write-Host $yaml -ForegroundColor DarkGray
    $yaml | kubectl apply -f -
    Step "new caps in force"
    Run "kubectl describe resourcequota bad-tenant-quota -n bad-tenant"
    if (Confirm "`nAlso SAVE these values into resourcequota.yml (permanent)?") {
        Set-Content -Path (Join-Path $Root "resourcequota.yml") -Value $yaml -Encoding UTF8
        Write-Host "Saved to resourcequota.yml." -ForegroundColor Green
    }
    Write-Host "`nTip: requests.cpu is the key cap - with $rc CPU and 1-CPU attacker pods," -ForegroundColor Gray
    Write-Host "the attacker can create at most $rc pods before the quota rejects the rest." -ForegroundColor Gray
    Pause-Key
}

# ---------- MONITORING: Grafana + Prometheus ----------
$MonRelease = "cep-mon"
$MonNamespace = "monitoring"

function Test-Helm {
    # already on PATH?
    if (Get-Command helm -ErrorAction SilentlyContinue) { return $true }

    # Not on this session's PATH. winget installs Helm but doesn't refresh the
    # PATH of an already-open window, so look for it where winget drops it and
    # add that folder to the PATH for this session.
    $search = @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages",
        "$env:ProgramData\chocolatey\lib\kubernetes-helm",
        "$env:ProgramFiles\Helm"
    ) | Where-Object { Test-Path $_ }

    foreach ($base in $search) {
        $exe = Get-ChildItem $base -Recurse -Filter helm.exe -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($exe) {
            $env:Path = "$($exe.DirectoryName);$env:Path"
            Write-Host "  (found Helm at $($exe.FullName) - added to PATH for this session)" -ForegroundColor DarkGray
            return $true
        }
    }

    Write-Host "`n  [!] 'helm' is not installed or not on PATH." -ForegroundColor Red
    Write-Host "      If you just installed it, close this window and reopen the runner." -ForegroundColor Gray
    Write-Host "      To install:" -ForegroundColor Gray
    Write-Host "        winget install Helm.Helm --source winget" -ForegroundColor DarkGray
    Write-Host "        choco install kubernetes-helm" -ForegroundColor DarkGray
    return $false
}

function Setup-Monitoring {
    Title "G. Set up Grafana + Prometheus monitoring"
    if (-not (Test-Helm)) { Pause-Key; return }
    Write-Host "Installs Prometheus + kube-state-metrics + node-exporter + Grafana into the" -ForegroundColor Gray
    Write-Host "'$MonNamespace' namespace, then imports the custom CEP dashboard." -ForegroundColor Gray
    Write-Host "First run pulls several images and can take 3-6 minutes." -ForegroundColor Gray
    if (-not (Confirm "Install the monitoring stack now?")) { return }

    Step "add the prometheus-community Helm repo"
    Run "helm repo add prometheus-community https://prometheus-community.github.io/helm-charts"
    Run "helm repo update"

    Step "install / upgrade the kube-prometheus-stack (release '$MonRelease')"
    Run "helm upgrade --install $MonRelease prometheus-community/kube-prometheus-stack -n $MonNamespace --create-namespace -f monitoring\kube-prometheus-stack-values.yaml"

    Step "wait for Grafana to be ready"
    Run "kubectl -n $MonNamespace rollout status deploy/$MonRelease-grafana --timeout=240s"

    Step "import the custom CEP dashboard (as a labelled ConfigMap the Grafana sidecar auto-loads)"
    Run "kubectl create configmap cep-grafana-dashboard -n $MonNamespace --from-file=monitoring\cep-dashboard.json --dry-run=client -o yaml | kubectl apply -f -"
    Run "kubectl label configmap cep-grafana-dashboard -n $MonNamespace grafana_dashboard=1 --overwrite"

    Write-Host "`nMonitoring is up. Press V to open the Grafana dashboard." -ForegroundColor Green
    Pause-Key
}

function Open-Grafana {
    Title "V. Open the Grafana dashboard"
    $svc = (kubectl get svc "$MonRelease-grafana" -n $MonNamespace 2>&1 | Out-String)
    if ($svc -match "NotFound" -or $svc -match "Error") {
        Write-Host "`n  [!] Grafana isn't installed yet. Run option G first." -ForegroundColor Yellow
        Pause-Key; return
    }
    Write-Host "Login:  user = admin   password = cep-admin" -ForegroundColor Cyan
    Step "making sure Grafana has finished starting (first boot can take a few minutes)"
    Run "kubectl -n $MonNamespace rollout status deploy/$MonRelease-grafana --timeout=360s"
    Write-Host "A new window will hold the port-forward open. Leave it open while you view Grafana." -ForegroundColor Gray
    Step "starting port-forward localhost:3000 -> grafana:80 (new window)"
    $pf = "Set-Location '$Root'; Write-Host 'GRAFANA port-forward - leave this open' -ForegroundColor Cyan; kubectl -n $MonNamespace port-forward svc/$MonRelease-grafana 3000:80"
    Start-Process powershell -ArgumentList "-NoExit","-Command",$pf
    Start-Sleep -Seconds 4
    Step "opening the CEP dashboard in your browser"
    Start-Process "http://localhost:3000/d/cep-preempt-dos/cep-pod-priority-preemption-dos?refresh=5s"
    Write-Host "`nIf the browser opened before Grafana was ready, just refresh the page." -ForegroundColor Gray
    Pause-Key
}

function Remove-Monitoring {
    Title "GX. Remove the monitoring stack"
    if (-not (Confirm "Uninstall Grafana/Prometheus and delete the '$MonNamespace' namespace?")) { return }
    Run "helm uninstall $MonRelease -n $MonNamespace"
    Run "kubectl delete namespace $MonNamespace --ignore-not-found"
    Write-Host "`nMonitoring stack removed." -ForegroundColor Green
    Pause-Key
}

# ---------- menu ----------
function Show-Menu {
    Clear-Host
    Title "Pod Priority Preemption DoS In Multi Tenant Environment"
    Write-Host "  Recommended order: S -> 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8`n" -ForegroundColor DarkGray
    Write-Host "  SETUP"
    Write-Host "    S  Start the Minikube cluster (run this first!)" -ForegroundColor Green
    Write-Host "    0  Preflight check (is everything ready?)"
    Write-Host "    1  Start the live detector      (new window)"
    Write-Host "    2  Start the live victim watch  (new window)"
    Write-Host "`n  ATTACK (undefended)" -ForegroundColor Red
    Write-Host "    3  Turn defenses OFF"
    Write-Host "    4  Launch the attack"
    Write-Host "    5  Show cluster state (victims evicted)"
    Write-Host "`n  DEFEND" -ForegroundColor Green
    Write-Host "    6  Apply all three mitigations"
    Write-Host "    7  Re-run attack  -> blocked at admission"
    Write-Host "`n  MONITORING (Grafana)" -ForegroundColor Blue
    Write-Host "    G  Set up Grafana + Prometheus (one time)"
    Write-Host "    V  Open the Grafana dashboard (port-forward)"
    Write-Host "    GX Remove the monitoring stack"
    Write-Host "`n  WRAP UP"
    Write-Host "    8  Show results (dashboard + comparison)"
    Write-Host "    9  Reset the demo"
    Write-Host "    D  Open the dashboard only"
    Write-Host "`n  MORE" -ForegroundColor Magenta
    Write-Host "    I  Inspect specs (attack + caps + classes, read-only)"
    Write-Host "    T  Defense status board (what is applied now?)"
    Write-Host "    L  View the detector log (preemption_log.csv)"
    Write-Host "    C  Clean up attacker pods only (reset baseline)"
    Write-Host "    M0 Remove ALL mitigations (clean slate)"
    Write-Host "    M1 Apply ONLY ResourceQuota"
    Write-Host "    M2 Apply ONLY non-preempting class (+ demo)"
    Write-Host "    M3 Apply ONLY Kyverno policy"
    Write-Host "    E  Edit the resource caps (CPU/mem/pods)"
    Write-Host "    X  Custom attack (choose pods / CPU / class)"
    Write-Host "    N  View / add cluster nodes"
    Write-Host "`n    Q  Quit`n"
    Write-Host "Choose: " -ForegroundColor Cyan -NoNewline
}

:menu while ($true) {
    Show-Menu
    switch ((Read-Host).Trim().ToUpper()) {
        "S" { Start-Cluster }
        "0" { Preflight }
        "1" { Start-Detector }
        "2" { Start-Watch }
        "3" { Mitigations-Off }
        "4" { Attack }
        "5" { Show-State }
        "6" { Mitigations-On }
        "7" { Attack-Blocked }
        "G" { Setup-Monitoring }
        "V" { Open-Grafana }
        "GX" { Remove-Monitoring }
        "8" { Show-Results }
        "9" { Reset-Demo }
        "D" { Start-Process (Join-Path $Root "dashboard.html") }
        "I" { Show-Specs }
        "T" { Defense-Status }
        "L" { View-Detector-Log }
        "C" { Cleanup-Attack }
        "M0" { Clear-All-Mitigations }
        "M1" { Apply-M1 }
        "M2" { Apply-M2 }
        "M3" { Apply-M3 }
        "E" { Edit-Quota }
        "X" { Custom-Attack }
        "N" { Node-Manage }
        "Q" { Write-Host "Bye." -ForegroundColor Cyan; break menu }
        default { }
    }
}

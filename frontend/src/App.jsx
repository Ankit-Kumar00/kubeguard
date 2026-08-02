import { useState, useEffect } from "react";
import { scanYaml, generateReport, fetchHistory, deleteHistoryItem } from "./services/api";

// Code Templates
const TEMPLATE_HARDENED = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secured-web-app
  labels:
    app: secured-web-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secured-web-app
  template:
    metadata:
      labels:
        app: secured-web-app
    spec:
      hostNetwork: false
      hostPID: false
      hostIPC: false
      seccompProfile:
        type: RuntimeDefault
      containers:
        - name: main-container
          image: nginx:1.25.3-alpine
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "250m"
              memory: "256Mi"
          securityContext:
            privileged: false
            runAsUser: 10001
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true`;

const TEMPLATE_INSECURE = `apiVersion: v1
kind: Pod
metadata:
  name: root-shell-backdoor
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  volumes:
    - name: host-root
      hostPath:
        path: /
  containers:
    - name: alpine-shell
      image: alpine:latest
      command: ["/bin/sh", "-c", "sleep 3600"]
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: false`;

const TEMPLATE_MEDIUM = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: standard-app
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web-node
          image: node:18
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
          securityContext:
            runAsUser: 1000
            allowPrivilegeEscalation: false`;

const KUBEGUARD_RULES = [
  { id: "KG-001", name: "Host Network Isolation", category: "Networking", severity: "High", risk: "Allows container processes to sniff host traffic.", fix: "Set spec.hostNetwork to false." },
  { id: "KG-002", name: "Host PID Namespace", category: "Isolation", severity: "Critical", risk: "Enables containers to view and interact with host processes.", fix: "Set spec.hostPID to false." },
  { id: "KG-003", name: "Host IPC Namespace", category: "Isolation", severity: "High", risk: "Allows containers to access host shared memory.", fix: "Set spec.hostIPC to false." },
  { id: "KG-004", name: "Missing Seccomp Profile", category: "Hardening", severity: "Medium", risk: "Broadens system call exploit surfaces.", fix: "Set spec.seccompProfile.type to 'RuntimeDefault'." },
  { id: "KG-005", name: "HostPath Storage Mount", category: "Hardening", severity: "High", risk: "Allows container access to host filesystem assets.", fix: "Use PersistentVolumeClaims instead." },
  { id: "KG-006", name: "Privileged Execution Mode", category: "Access Control", severity: "Critical", risk: "Grants container processes host root shell capability.", fix: "Set securityContext.privileged to false." },
  { id: "KG-007", name: "Container Running as Root", category: "Access Control", severity: "High", risk: "Gives attackers admin execution authority if container is breached.", fix: "Set securityContext.runAsNonRoot to true." },
  { id: "KG-008", name: "Privilege Escalation Allowed", category: "Access Control", severity: "High", risk: "Enables container subprocesses to escalate privileges.", fix: "Set securityContext.allowPrivilegeEscalation to false." },
  { id: "KG-009", name: "Writable Root Filesystem", category: "Hardening", severity: "Medium", risk: "Allows malicious files to write onto container storage.", fix: "Set securityContext.readOnlyRootFilesystem to true." },
  { id: "KG-010", name: "Tagless or 'latest' Image", category: "Hardening", severity: "Medium", risk: "Exposes configuration builds to unexpected tags/digests.", fix: "Pin images to specific semver tags." },
  { id: "KG-011", name: "Missing CPU / Memory Limits", category: "Resources", severity: "Medium", risk: "Permits resource starvation of node neighbors.", fix: "Define resources.limits CPU and Memory." },
  { id: "KG-012", name: "Missing CPU / Memory Requests", category: "Resources", severity: "Medium", risk: "Scheduler cannot allocate pod workloads efficiently.", fix: "Define resources.requests CPU and Memory." }
];

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard"); // "dashboard" | "scanner" | "history" | "standards" | "about"
  const [yamlCode, setYamlCode] = useState(TEMPLATE_INSECURE);
  const [fileName, setFileName] = useState("backdoor_pod.yaml");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [dbConnected, setDbConnected] = useState(false);
  const [activeFilter, setActiveFilter] = useState("all");
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [historySearch, setHistorySearch] = useState("");

  // Load history on mount
  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      const data = await fetchHistory();
      if (data.success) {
        setHistory(data.history || []);
        setDbConnected(data.dbConnected);
      }
    } catch (err) {
      console.warn("Backend database unavailable, using localStorage fallback.");
      const saved = localStorage.getItem("kubeguard-history");
      if (saved) {
        setHistory(JSON.parse(saved));
      }
    }
  };

  const handleTemplateSelect = (type) => {
    if (type === "hardened") {
      setYamlCode(TEMPLATE_HARDENED);
      setFileName("secured_deployment.yaml");
      showToast("success", "Loaded hardened deployment template");
    } else if (type === "insecure") {
      setYamlCode(TEMPLATE_INSECURE);
      setFileName("backdoor_pod.yaml");
      showToast("success", "Loaded insecure backdoor pod template");
    } else {
      setYamlCode(TEMPLATE_MEDIUM);
      setFileName("standard_app.yaml");
      showToast("success", "Loaded standard application template");
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      setYamlCode(event.target.result);
      showToast("success", `Loaded file: ${file.name}`);
    };
    reader.readAsText(file);
  };

  // Dedicated file scan from home dashboard without tab redirection
  const handleDashboardUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setIsScanning(true);
    setErrorMsg("");
    showToast("success", `Analyzing uploaded manifest: ${file.name}`);

    const reader = new FileReader();
    reader.onload = async (event) => {
      const fileContent = event.target.result;
      setYamlCode(fileContent);
      setFileName(file.name);

      try {
        const data = await scanYaml(fileContent, file.name);
        if (data.success) {
          setScanResult(data);
          showToast("success", `Audit complete for ${file.name}. Score: ${data.securityScore}/100`);
          await loadHistory();

          if (!dbConnected) {
            const newScan = {
              _id: `local_${Date.now()}`,
              fileName: data.fileName,
              securityScore: data.securityScore,
              severityCounts: data.severityCounts,
              findings: data.findings,
              recommendations: data.recommendations,
              scannedAt: data.scannedAt || new Date().toISOString()
            };
            const updated = [newScan, ...history.filter(h => !h._id.startsWith("local_"))];
            setHistory(updated);
            localStorage.setItem("kubeguard-history", JSON.stringify(updated));
          }
        } else {
          throw new Error(data.message || "Scan failed");
        }
      } catch (err) {
        setErrorMsg(err.message || "Failed to parse YAML manifest");
        showToast("error", err.message || "Failed to scan manifest");
      } finally {
        setIsScanning(false);
        e.target.value = ""; // clear input
      }
    };
    reader.readAsText(file);
  };

  const handleScan = async () => {
    if (!yamlCode.trim()) {
      showToast("error", "YAML input cannot be empty");
      return;
    }

    setIsScanning(true);
    setErrorMsg("");
    setScanResult(null);

    try {
      const data = await scanYaml(yamlCode, fileName);
      if (data.success) {
        setScanResult(data);
        showToast("success", "Security scan completed successfully");
        
        await loadHistory();
        
        if (!dbConnected) {
          const newScan = {
            _id: `local_${Date.now()}`,
            fileName: data.fileName,
            securityScore: data.securityScore,
            severityCounts: data.severityCounts,
            findings: data.findings,
            recommendations: data.recommendations,
            scannedAt: data.scannedAt || new Date().toISOString()
          };
          const updated = [newScan, ...history.filter(h => !h._id.startsWith("local_"))];
          setHistory(updated);
          localStorage.setItem("kubeguard-history", JSON.stringify(updated));
        }
      } else {
        throw new Error(data.message || "Assessment failed");
      }
    } catch (err) {
      setErrorMsg(err.message || "Failed to parse YAML manifest");
      showToast("error", err.message || "Failed to scan manifest");
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadHistoryItem = (item) => {
    setScanResult({
      fileName: item.fileName,
      securityScore: item.securityScore,
      severityCounts: item.severityCounts,
      findings: item.findings,
      recommendations: item.recommendations,
      scannedAt: item.scannedAt
    });
    setFileName(item.fileName);
    setActiveTab("scanner");
    showToast("success", `Loaded report: ${item.fileName}`);
  };

  const handleDeleteHistoryItem = async (e, id) => {
    e.stopPropagation();
    if (!confirm("Are you sure you want to delete this report?")) return;

    try {
      if (dbConnected && !id.toString().startsWith("local_")) {
        await deleteHistoryItem(id);
      }
      
      const updated = history.filter((item) => item._id !== id);
      setHistory(updated);
      localStorage.setItem("kubeguard-history", JSON.stringify(updated));
      showToast("success", "Report deleted");
      
      if (scanResult && scanResult._id === id) {
        setScanResult(null);
      }
    } catch (err) {
      showToast("error", "Deletion failed");
    }
  };

  const handleDownloadPDF = async () => {
    if (!scanResult) return;
    try {
      await generateReport(scanResult);
      showToast("success", "PDF Report downloaded");
    } catch (err) {
      showToast("error", "Failed to compile PDF Report");
    }
  };

  const showToast = (type, message) => {
    if (type === "success") {
      setSuccessMsg(message);
      setTimeout(() => setSuccessMsg(""), 4000);
    } else {
      setErrorMsg(message);
      setTimeout(() => setErrorMsg(""), 5000);
    }
  };

  const score = scanResult ? scanResult.securityScore : 100;
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let scoreColor = "stroke-emerald-500 text-emerald-500";
  let scoreBadge = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
  if (score < 50) {
    scoreColor = "stroke-rose-500 text-rose-500";
    scoreBadge = "bg-rose-500/10 text-rose-400 border-rose-500/20";
  } else if (score < 70) {
    scoreColor = "stroke-orange-500 text-orange-500";
    scoreBadge = "bg-orange-500/10 text-orange-400 border-orange-500/20";
  } else if (score < 90) {
    scoreColor = "stroke-amber-500 text-amber-500";
    scoreBadge = "bg-amber-500/10 text-amber-400 border-amber-500/20";
  }

  // Dashboard Aggregates
  const totalScans = history.length;
  const avgScore = totalScans > 0 
    ? Math.round(history.reduce((acc, curr) => acc + curr.securityScore, 0) / totalScans)
    : 100;
  
  let complianceStatus = "High Compliance";
  let complianceColor = "text-emerald-400";
  if (avgScore < 60) {
    complianceStatus = "Critical Security Warnings";
    complianceColor = "text-rose-400";
  } else if (avgScore < 85) {
    complianceStatus = "Needs Optimization";
    complianceColor = "text-amber-400";
  }

  const filteredFindings = scanResult
    ? scanResult.findings.filter((f) => {
        if (activeFilter === "all") return true;
        return f.severity?.toLowerCase() === activeFilter;
      })
    : [];

  const getCategoryStats = () => {
    if (!scanResult) return { Networking: 0, Isolation: 0, Hardening: 0, "Access Control": 0, Resources: 0 };
    const stats = { Networking: 0, Isolation: 0, Hardening: 0, "Access Control": 0, Resources: 0 };
    scanResult.findings.forEach((item) => {
      if (stats[item.category] !== undefined) stats[item.category]++;
    });
    return stats;
  };
  const categoryStats = getCategoryStats();

  const filteredHistory = history.filter(h => 
    h.fileName.toLowerCase().includes(historySearch.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#09090b] text-[#f4f4f5] flex flex-col antialiased">
      
      {/* Top Navbar */}
      <header className="border-b border-[#27272a] bg-[#18181b] px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-[#27272a] rounded-lg border border-[#3f3f46] text-indigo-400">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white">KubeGuard Portal</h1>
                <span className="text-[10px] font-bold bg-[#27272a] text-indigo-400 px-2 py-0.5 rounded border border-[#3f3f46]">ENTERPRISE</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <span className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold border ${dbConnected ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-amber-500/10 border-amber-500/20 text-amber-400"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${dbConnected ? "bg-emerald-500" : "bg-amber-500"}`}></span>
              {dbConnected ? "MongoDB Active" : "Local Sandbox Storage"}
            </span>
          </div>

        </div>
      </header>

      {/* Toast Notifications */}
      <div className="fixed top-20 right-6 z-50 max-w-sm flex flex-col gap-2.5 pointer-events-none">
        {successMsg && (
          <div className="bg-[#18181b] border border-emerald-500/30 text-emerald-300 p-4 rounded-xl shadow-xl flex items-center gap-3 animate-fade-in">
            <div className="p-1.5 bg-emerald-500/15 text-emerald-400 rounded-md">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="text-xs font-semibold">{successMsg}</p>
          </div>
        )}
        {errorMsg && (
          <div className="bg-[#18181b] border border-rose-500/30 text-rose-300 p-4 rounded-xl shadow-xl flex items-center gap-3 animate-fade-in">
            <div className="p-1.5 bg-rose-500/15 text-rose-400 rounded-md">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
            </div>
            <p className="text-xs font-semibold">{errorMsg}</p>
          </div>
        )}
      </div>

      {/* Main Workspace Frame */}
      <div className="flex-grow max-w-7xl w-full mx-auto p-4 md:p-6 grid lg:grid-cols-12 gap-6 items-start">
        
        {/* Navigation Sidebar */}
        <aside className="lg:col-span-2 flex lg:flex-col gap-1.5 bg-[#18181b] border border-[#27272a] p-2 rounded-xl">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`nav-btn ${activeTab === "dashboard" ? "nav-btn-active" : ""}`}
          >
            <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25a2.25 2.25 0 01-2.25 2.25h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
            </svg>
            Overview
          </button>

          <button
            onClick={() => setActiveTab("scanner")}
            className={`nav-btn ${activeTab === "scanner" ? "nav-btn-active" : ""}`}
          >
            <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />
            </svg>
            YAML Scanner
          </button>
          
          <button
            onClick={() => setActiveTab("history")}
            className={`nav-btn ${activeTab === "history" ? "nav-btn-active" : ""}`}
          >
            <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
            </svg>
            Scan Database
          </button>
          
          <button
            onClick={() => setActiveTab("standards")}
            className={`nav-btn ${activeTab === "standards" ? "nav-btn-active" : ""}`}
          >
            <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.375M9 9h3.375m0 9H18a2.25 2.25 0 002.25-2.25V5.25A2.25 2.25 0 0018 3H6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 006 21h6m4.5-4.5H18M12 3v18" />
            </svg>
            Rule Catalog
          </button>
          
          <button
            onClick={() => setActiveTab("about")}
            className={`nav-btn ${activeTab === "about" ? "nav-btn-active" : ""}`}
          >
            <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 111.063.852l-.708 2.836a.75.75 0 001.063.852l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
            </svg>
            System Info
          </button>
        </aside>

        {/* Content Tabs */}
        <div className="lg:col-span-10 grid lg:grid-cols-12 gap-6 items-start">
          
          {/* TAB 0: DASHBOARD LANDING HOMEPAGE */}
          {activeTab === "dashboard" && (
            <div className="lg:col-span-12 flex flex-col gap-6 animate-fade-in">
              
              {/* Spacious Welcome Banner */}
              <div className="saas-card rounded-xl p-8 bg-gradient-to-br from-[#1c1917]/20 to-[#18181b] border-[#27272a] flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                <div className="max-w-xl">
                  <h2 className="text-2xl font-bold text-white tracking-tight">Enterprise Kubernetes Guard</h2>
                  <p className="text-sm text-[#a1a1aa] mt-2 leading-relaxed">
                    Shift security left by auditing your resource definitions against NSA & CISA hardening guidelines. Catch misconfigurations before they reach deployment.
                  </p>
                </div>
                
                {/* File scan trigger inline */}
                <div>
                  <label
                    htmlFor="dashboard-scan-upload"
                    className="px-5 py-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs uppercase tracking-wider transition shadow-lg shadow-indigo-500/10 cursor-pointer flex items-center gap-2"
                  >
                    <svg className="w-4 h-4 text-white animate-pulse" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                    </svg>
                    Upload & Scan File
                  </label>
                  <input
                    type="file"
                    id="dashboard-scan-upload"
                    accept=".yaml,.yml"
                    onChange={handleDashboardUpload}
                    className="hidden"
                  />
                </div>
              </div>

              {/* Large Metric Cards */}
              <div className="grid md:grid-cols-4 gap-4">
                <div className="saas-card rounded-xl p-6">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Total Audited Scans</span>
                  <h3 className="text-3xl font-bold text-white mt-2">{totalScans}</h3>
                  <p className="text-[11px] text-slate-500 mt-1">Files in database history</p>
                </div>

                <div className="saas-card rounded-xl p-6">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Compliance Average</span>
                  <h3 className={`text-3xl font-bold mt-2 ${complianceColor}`}>{avgScore}%</h3>
                  <p className="text-[11px] text-slate-500 mt-1">{complianceStatus}</p>
                </div>

                <div className="saas-card rounded-xl p-6">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Security Policies</span>
                  <h3 className="text-3xl font-bold text-indigo-400 mt-2">12 Rules</h3>
                  <p className="text-[11px] text-slate-500 mt-1">Active vulnerability checks</p>
                </div>

                <div className="saas-card rounded-xl p-6">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Cluster Status</span>
                  <h3 className="text-3xl font-bold text-emerald-400 mt-2">Low Risk</h3>
                  <p className="text-[11px] text-slate-500 mt-1">Based on compliance scores</p>
                </div>
              </div>

              {/* Quick Navigation Cards */}
              <div className="grid md:grid-cols-3 gap-6">
                <div 
                  onClick={() => setActiveTab("scanner")}
                  className="saas-card rounded-xl p-6 cursor-pointer hover:border-indigo-500/60 transition group"
                >
                  <div className="p-3 bg-[#27272a] rounded-lg text-indigo-400 w-11 h-11 flex items-center justify-center border border-[#3f3f46] group-hover:border-indigo-500/40 transition">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
                    </svg>
                  </div>
                  <h4 className="text-sm font-bold text-white mt-4 uppercase tracking-wider">YAML Scanner</h4>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    Paste manifest files directly or load preset templates to inspect and download assessments.
                  </p>
                </div>

                <div 
                  onClick={() => setActiveTab("history")}
                  className="saas-card rounded-xl p-6 cursor-pointer hover:border-indigo-500/60 transition group"
                >
                  <div className="p-3 bg-[#27272a] rounded-lg text-indigo-400 w-11 h-11 flex items-center justify-center border border-[#3f3f46] group-hover:border-indigo-500/40 transition">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
                    </svg>
                  </div>
                  <h4 className="text-sm font-bold text-white mt-4 uppercase tracking-wider">Scan Database</h4>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    View previous scan logs, search audit records, and delete outdated entries.
                  </p>
                </div>

                <div 
                  onClick={() => setActiveTab("standards")}
                  className="saas-card rounded-xl p-6 cursor-pointer hover:border-indigo-500/60 transition group"
                >
                  <div className="p-3 bg-[#27272a] rounded-lg text-indigo-400 w-11 h-11 flex items-center justify-center border border-[#3f3f46] group-hover:border-indigo-500/40 transition">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.375M9 9h3.375m0 9H18a2.25 2.25 0 002.25-2.25V5.25A2.25 2.25 0 0018 3H6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 006 21h6m4.5-4.5H18M12 3v18" />
                    </svg>
                  </div>
                  <h4 className="text-sm font-bold text-white mt-4 uppercase tracking-wider">Rule Standards</h4>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    Inspect the security policy rules checked by the scanning engine.
                  </p>
                </div>
              </div>

              {/* Recent Activity Table */}
              <div className="saas-card rounded-xl p-6">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider border-b border-[#27272a] pb-3">Recent Security Audits</h4>
                
                {history.length === 0 ? (
                  <div className="text-center py-8 text-slate-500 text-xs">
                    No audits found. Execute a scan to populate dashboard logs.
                  </div>
                ) : (
                  <div className="overflow-x-auto mt-3">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="text-slate-500 uppercase text-[9px] tracking-wider border-b border-[#27272a]">
                          <th className="py-2.5">Manifest File</th>
                          <th className="py-2.5">Date</th>
                          <th className="py-2.5">Score</th>
                          <th className="py-2.5 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.slice(0, 4).map((scan) => (
                          <tr key={scan._id} className="border-b border-[#27272a]/50 hover:bg-[#27272a]/10 transition">
                            <td className="py-3 font-semibold text-slate-300 font-mono">{scan.fileName}</td>
                            <td className="py-3 text-slate-400">{new Date(scan.scannedAt).toLocaleDateString()}</td>
                            <td className="py-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${scan.securityScore >= 90 ? "text-emerald-400 bg-emerald-500/10" : scan.securityScore >= 70 ? "text-amber-400 bg-amber-500/10" : "text-rose-400 bg-rose-500/10"}`}>
                                {scan.securityScore} / 100
                              </span>
                            </td>
                            <td className="py-3 text-right">
                              <button
                                onClick={() => handleLoadHistoryItem(scan)}
                                className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 hover:text-indigo-300 transition"
                              >
                                View Report
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

            </div>
          )}

          {/* TAB 1: WORKSPACE */}
          {activeTab === "scanner" && (
            <>
              {/* Manifest Editor Panel */}
              <div className="lg:col-span-6 flex flex-col gap-5">
                <div className="saas-card rounded-xl p-5 flex flex-col gap-4">
                  
                  <div className="flex justify-between items-center border-b border-[#27272a] pb-3">
                    <h2 className="text-xs font-bold text-[#a1a1aa] uppercase tracking-wider">Manifest Code Workspace</h2>
                    
                    <label className="text-[11px] font-semibold px-2.5 py-1.5 bg-[#27272a] hover:bg-[#3f3f46] text-white rounded-md cursor-pointer transition flex items-center gap-1.5 border border-[#3f3f46]">
                      <svg className="w-3.5 h-3.5 text-indigo-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                      </svg>
                      Import File
                      <input type="file" accept=".yaml,.yml" onChange={handleFileUpload} className="hidden" />
                    </label>
                  </div>

                  {/* Preset Configurations */}
                  <div className="bg-[#09090b] border border-[#27272a] p-3 rounded-lg flex flex-col gap-2">
                    <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Select Demo Config Template</p>
                    <div className="grid grid-cols-3 gap-2 mt-1">
                      <button
                        onClick={() => handleTemplateSelect("insecure")}
                        className="py-1.5 px-2 text-[10px] font-semibold rounded bg-rose-500/10 border border-rose-500/20 hover:bg-rose-500/15 text-rose-400 transition"
                      >
                        Insecure Pod
                      </button>
                      <button
                        onClick={() => handleTemplateSelect("basic")}
                        className="py-1.5 px-2 text-[10px] font-semibold rounded bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/15 text-amber-400 transition"
                      >
                        Standard App
                      </button>
                      <button
                        onClick={() => handleTemplateSelect("hardened")}
                        className="py-1.5 px-2 text-[10px] font-semibold rounded bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/15 text-emerald-400 transition"
                      >
                        Hardened App
                      </button>
                    </div>
                  </div>

                  {/* Filename Descriptor */}
                  <div className="flex items-center gap-2 bg-[#09090b] border border-[#27272a] px-3 py-2 rounded-lg text-slate-400 text-xs">
                    <span className="font-mono text-[#71717a] text-[9px] uppercase font-bold">File name:</span>
                    <input 
                      type="text" 
                      value={fileName} 
                      onChange={(e) => setFileName(e.target.value)}
                      className="bg-transparent focus:outline-none w-full font-mono text-slate-200"
                    />
                  </div>

                  {/* Code Area */}
                  <textarea
                    value={yamlCode}
                    onChange={(e) => setYamlCode(e.target.value)}
                    className="w-full h-[400px] editor-textarea p-4 rounded-lg focus:border-indigo-500/50"
                    placeholder="Enter manifest description here..."
                    spellCheck="false"
                  />

                  {/* Analyze Action Trigger */}
                  <button
                    onClick={handleScan}
                    disabled={isScanning}
                    className={`w-full py-3.5 px-6 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition duration-200 border bg-indigo-600 hover:bg-indigo-500 text-white shadow-md border-transparent ${isScanning ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                  >
                    {isScanning ? (
                      <>
                        <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Inspecting posture...
                      </>
                    ) : (
                      <>
                        <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
                        </svg>
                        Execute posture scan
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Assessment Panel */}
              <div className="lg:col-span-6 flex flex-col gap-5">
                {!scanResult ? (
                  <div className="saas-card rounded-xl p-10 flex flex-col items-center justify-center text-center min-h-[660px] border-[#27272a]">
                    <div className="w-16 h-16 rounded-xl bg-[#27272a] border border-[#3f3f46] flex items-center justify-center text-slate-400 mb-6">
                      <svg className="w-8 h-8" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    </div>
                    <h3 className="text-sm font-bold uppercase tracking-wider text-white">Assessment Data Empty</h3>
                    <p className="text-xs text-[#a1a1aa] max-w-xs mt-2 leading-relaxed">
                      Upload a file or choose a template preset. Click "Execute posture scan" to compute security evaluations.
                    </p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-5 animate-fade-in">
                    
                    {/* Score Bar widget */}
                    <div className="saas-card rounded-xl p-5 bg-[#18181b]">
                      <div className="flex flex-col sm:flex-row items-center gap-6">
                        
                        {/* Circular Gauge */}
                        <div className="flex justify-center relative">
                          <svg className="w-28 h-28 transform -rotate-90">
                            <circle cx="56" cy="56" r="46" className="stroke-zinc-800 fill-none" strokeWidth="6" />
                            <circle
                              cx="56"
                              cy="56"
                              r="46"
                              className={`fill-none transition-all duration-700 ease-out ${scoreColor}`}
                              strokeWidth="6"
                              strokeDasharray={2 * Math.PI * 46}
                              strokeDashoffset={2 * Math.PI * 46 - (score / 100) * (2 * Math.PI * 46)}
                              strokeLinecap="round"
                            />
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-2xl font-bold tracking-tight text-white">{score}</span>
                            <span className="text-[8px] font-bold text-[#71717a] tracking-wider uppercase">Score</span>
                          </div>
                        </div>

                        {/* File Details & Download */}
                        <div className="flex-grow text-center sm:text-left flex flex-col gap-2.5">
                          <div>
                            <h4 className="text-sm font-bold text-white uppercase tracking-wider">{scanResult.fileName}</h4>
                            <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">
                              Scanned at {new Date(scanResult.scannedAt).toLocaleTimeString()}
                            </p>
                          </div>
                          
                          <button
                            onClick={handleDownloadPDF}
                            className="px-3 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition self-center sm:self-start border border-transparent"
                          >
                            <svg className="w-3.5 h-3.5 text-white" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                            </svg>
                            Export PDF Assessment
                          </button>
                        </div>

                      </div>
                    </div>

                    {/* Threat Count pills */}
                    <div className="grid grid-cols-4 gap-3">
                      <div className="saas-card rounded-lg p-3 text-center border-l-4 border-rose-500">
                        <p className="text-[9px] font-bold uppercase text-slate-400">Critical</p>
                        <h4 className="text-base font-bold text-rose-500 mt-0.5">{scanResult.severityCounts?.critical || 0}</h4>
                      </div>
                      <div className="saas-card rounded-lg p-3 text-center border-l-4 border-orange-500">
                        <p className="text-[9px] font-bold uppercase text-slate-400">High</p>
                        <h4 className="text-base font-bold text-orange-500 mt-0.5">{scanResult.severityCounts?.high || 0}</h4>
                      </div>
                      <div className="saas-card rounded-lg p-3 text-center border-l-4 border-amber-500">
                        <p className="text-[9px] font-bold uppercase text-slate-400">Medium</p>
                        <h4 className="text-base font-bold text-amber-500 mt-0.5">{scanResult.severityCounts?.medium || 0}</h4>
                      </div>
                      <div className="saas-card rounded-lg p-3 text-center border-l-4 border-blue-500">
                        <p className="text-[9px] font-bold uppercase text-slate-400">Low</p>
                        <h4 className="text-base font-bold text-blue-500 mt-0.5">{scanResult.severityCounts?.low || 0}</h4>
                      </div>
                    </div>

                    {/* Category Chart */}
                    <div className="saas-card rounded-xl p-4 flex flex-col gap-3">
                      <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Violations by category</h4>
                      
                      <div className="flex flex-col gap-2.5">
                        {Object.entries(categoryStats).map(([cat, val]) => {
                          const max = Math.max(...Object.values(categoryStats), 1);
                          const pct = (val / max) * 100;
                          let progressCol = "bg-indigo-600";
                          if (val > 0) {
                            if (cat === "Access Control" || cat === "Isolation") progressCol = "bg-rose-500";
                            else if (cat === "Networking") progressCol = "bg-orange-500";
                          }

                          return (
                            <div key={cat} className="flex flex-col gap-1 text-[11px]">
                              <div className="flex justify-between items-center text-slate-400">
                                <span className="font-semibold uppercase tracking-wider text-[10px]">{cat}</span>
                                <span className={`font-bold font-mono ${val > 0 ? "text-rose-400" : "text-slate-500"}`}>{val} rules</span>
                              </div>
                              <div className="w-full h-1 bg-[#09090b] rounded-full overflow-hidden border border-[#27272a]">
                                <div
                                  className={`h-full rounded-full progress-bar-fill ${progressCol}`}
                                  style={{ width: `${pct}%` }}
                                ></div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* List Filter bar */}
                    <div className="flex flex-col gap-3.5">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#27272a] pb-2">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-[#a1a1aa]">Inspection Results</h4>
                        
                        <div className="flex bg-[#09090b] border border-[#27272a] p-0.5 rounded-lg">
                          {["all", "critical", "high", "medium", "low"].map((filter) => (
                            <button
                              key={filter}
                              onClick={() => setActiveFilter(filter)}
                              className={`px-2 py-1 text-[9px] font-semibold uppercase rounded tracking-wider transition ${activeFilter === filter ? "bg-indigo-600 text-white font-bold" : "text-[#71717a] hover:text-slate-300"}`}
                            >
                              {filter}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Findings List */}
                      <div className="flex flex-col gap-3.5 max-h-[350px] overflow-y-auto pr-1">
                        {filteredFindings.length === 0 ? (
                          <div className="saas-card rounded-xl p-8 text-center text-slate-500 text-xs">
                            No violations identified for severity filter: <b className="capitalize text-slate-300">{activeFilter}</b>
                          </div>
                        ) : (
                          filteredFindings.map((item, idx) => {
                            let borderCol = "border-slate-800";
                            let tagCol = "bg-slate-800/40 text-slate-500 border-slate-700/20";
                            const sev = item.severity?.toLowerCase();
                            if (sev === "critical") {
                              borderCol = "border-l-4 border-l-rose-500";
                              tagCol = "bg-rose-500/10 text-rose-400 border-rose-500/20";
                            } else if (sev === "high") {
                              borderCol = "border-l-4 border-l-orange-500";
                              tagCol = "bg-orange-500/10 text-orange-400 border-orange-500/20";
                            } else if (sev === "medium") {
                              borderCol = "border-l-4 border-l-amber-500";
                              tagCol = "bg-amber-500/10 text-amber-400 border-amber-500/20";
                            } else if (sev === "low") {
                              borderCol = "border-l-4 border-l-sky-500";
                              tagCol = "bg-sky-500/10 text-sky-400 border-sky-500/20";
                            }

                            return (
                              <div
                                key={idx}
                                className={`saas-card rounded-xl p-4 border border-[#27272a] ${borderCol} flex flex-col gap-3`}
                              >
                                <div className="flex justify-between items-start gap-4">
                                  <div className="flex flex-col gap-1">
                                    <div className="flex items-center gap-1.5">
                                      <span className="text-[9px] font-mono font-bold bg-[#09090b] border border-[#27272a] px-1.5 py-0.5 rounded text-indigo-400">
                                        {item.id || `KG-10${idx}`}
                                      </span>
                                      <span className="text-[9px] font-bold uppercase bg-[#09090b] border border-[#27272a] px-1.5 py-0.5 rounded text-slate-400">
                                        {item.category}
                                      </span>
                                    </div>
                                    <h4 className="text-xs font-bold text-slate-200 mt-1 leading-normal">{item.message}</h4>
                                  </div>

                                  <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 border rounded ${tagCol}`}>
                                    {item.severity}
                                  </span>
                                </div>

                                <div className="text-[10px] font-mono text-slate-500 flex gap-1">
                                  <span>Resource:</span>
                                  <span className="text-slate-300 font-bold">{item.resource}</span>
                                </div>

                                {/* Remediation */}
                                <div className="bg-[#09090b] border border-[#27272a] border-l-2 border-l-emerald-500 rounded-lg p-3 flex items-start gap-2.5">
                                  <div className="p-1 bg-emerald-500/10 text-emerald-400 rounded">
                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 18a3.75 3.75 0 00.495-7.467 5.99 5.99 0 00-1.925 3.546 5.974 5.974 0 01-2.133-1A3.75 3.75 0 0012 18z" />
                                    </svg>
                                  </div>
                                  <div className="flex flex-col gap-0.5">
                                    <span className="text-[9px] font-bold text-emerald-400 uppercase tracking-widest">Remediation Action</span>
                                    <p className="text-[10.5px] text-slate-300 leading-relaxed font-medium">{item.remediation}</p>
                                  </div>
                                </div>

                              </div>
                            );
                          })
                        )}
                      </div>
                    </div>

                  </div>
                )}
              </div>
            </>
          )}

          {/* TAB 2: HISTORICAL LOGS TABLE */}
          {activeTab === "history" && (
            <div className="lg:col-span-12 saas-card rounded-xl p-5 flex flex-col gap-4 animate-fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#27272a] pb-3 gap-3">
                <div>
                  <h2 className="text-sm font-bold uppercase tracking-wider text-white">Assessment Logs</h2>
                  <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-widest mt-0.5">Historical scan records database catalog</p>
                </div>
                
                {/* Search */}
                <div className="bg-[#09090b] border border-[#27272a] px-3 py-1.5 rounded-lg text-xs flex items-center gap-2 max-w-xs w-full focus-within:border-indigo-500/30">
                  <svg className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.637 10.637z" />
                  </svg>
                  <input
                    type="text"
                    placeholder="Search logs by file name..."
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                    className="bg-transparent focus:outline-none w-full text-slate-300 text-[11px]"
                  />
                </div>
              </div>

              {filteredHistory.length === 0 ? (
                <div className="text-center py-16 text-slate-500 text-xs">
                  No historical reports found
                </div>
              ) : (
                <div className="grid md:grid-cols-2 gap-4">
                  {filteredHistory.map((scan) => {
                    let badgeCol = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
                    if (scan.securityScore < 50) badgeCol = "bg-rose-500/10 text-rose-400 border-rose-500/20";
                    else if (scan.securityScore < 70) badgeCol = "bg-orange-500/10 text-orange-400 border-orange-500/20";
                    else if (scan.securityScore < 90) badgeCol = "bg-amber-500/10 text-amber-400 border-amber-500/20";

                    return (
                      <div
                        key={scan._id}
                        onClick={() => handleLoadHistoryItem(scan)}
                        className="group flex flex-col p-4 rounded-lg border border-[#27272a] bg-[#09090b]/30 hover:bg-[#18181b] hover:border-[#3f3f46] cursor-pointer transition"
                      >
                        <div className="flex justify-between items-start gap-4">
                          <div className="min-w-0">
                            <h4 className="text-xs font-bold text-white truncate tracking-wide">{scan.fileName}</h4>
                            <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mt-1">
                              Scanned {new Date(scan.scannedAt).toLocaleDateString()} at {new Date(scan.scannedAt).toLocaleTimeString()}
                            </p>
                          </div>
                          
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border tracking-wider ${badgeCol}`}>
                            SCORE: {scan.securityScore}
                          </span>
                        </div>

                        {/* Counts */}
                        <div className="flex items-center justify-between border-t border-[#27272a] mt-4 pt-3 text-[9px] font-bold text-slate-500 uppercase tracking-wider">
                          <div className="flex gap-2.5">
                            <span className="text-rose-400">{scan.severityCounts?.critical || 0} CRITICAL</span>
                            <span>•</span>
                            <span className="text-orange-400">{scan.severityCounts?.high || 0} HIGH</span>
                          </div>

                          <button
                            onClick={(e) => handleDeleteHistoryItem(e, scan._id)}
                            className="text-[9px] font-bold tracking-widest bg-rose-500/10 border border-rose-500/20 text-rose-400 px-2 py-1 rounded hover:bg-rose-500/20 hover:text-rose-300 opacity-0 group-hover:opacity-100 transition"
                          >
                            DELETE RECORD
                          </button>
                        </div>

                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: RULE POLICY CATALOG */}
          {activeTab === "standards" && (
            <div className="lg:col-span-12 saas-card rounded-xl p-5 flex flex-col gap-4 animate-fade-in">
              <div className="border-b border-[#27272a] pb-3">
                <h2 className="text-sm font-bold uppercase tracking-wider text-white">Active Policy Catalog</h2>
                <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mt-0.5">Reference catalog for active inspection profiles</p>
              </div>

              <div className="flex flex-col gap-3">
                {KUBEGUARD_RULES.map((rule) => {
                  let tagBg = "bg-[#27272a] text-slate-500 border border-[#3f3f46]";
                  if (rule.severity === "Critical") tagBg = "bg-rose-500/10 border border-rose-500/20 text-rose-400";
                  else if (rule.severity === "High") tagBg = "bg-orange-500/10 border border-orange-500/20 text-orange-400";
                  else if (rule.severity === "Medium") tagBg = "bg-amber-500/10 border border-amber-500/20 text-amber-400";

                  return (
                    <div key={rule.id} className="p-4 rounded-lg border border-[#27272a] bg-[#18181b]/30 flex flex-col md:flex-row gap-4 items-start justify-between">
                      <div className="flex flex-col gap-2 max-w-3xl">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[9px] font-mono font-bold bg-[#09090b] border border-[#27272a] px-2 py-0.5 rounded text-indigo-400">{rule.id}</span>
                          <span className="text-[9px] font-bold uppercase tracking-wider bg-[#09090b] px-2 py-0.5 rounded text-slate-400 border border-[#27272a]">{rule.category}</span>
                          <h4 className="text-xs font-bold text-white tracking-wide uppercase">{rule.name}</h4>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed font-medium"><span className="text-slate-500 font-bold uppercase text-[9px] tracking-wider block md:inline md:mr-1">Vulnerability Impact:</span> {rule.risk}</p>
                        <p className="text-[11px] text-emerald-400/90 leading-relaxed font-semibold"><span className="text-emerald-500 font-bold uppercase text-[9px] tracking-wider block md:inline md:mr-1">Remediation Code:</span> {rule.fix}</p>
                      </div>

                      <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 border rounded ${tagBg} self-start md:self-auto`}>
                        {rule.severity}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 4: ARCHITECTURE */}
          {activeTab === "about" && (
            <div className="lg:col-span-12 saas-card rounded-xl p-6 flex flex-col gap-5 animate-fade-in">
              <div className="border-b border-[#27272a] pb-3">
                <h2 className="text-sm font-bold uppercase tracking-wider text-white">System Architecture Map</h2>
                <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mt-0.5">Underlying technology architecture map</p>
              </div>

              <div className="grid md:grid-cols-3 gap-6 mt-2">
                <div className="flex flex-col gap-2 bg-[#09090b]/50 border border-[#27272a] p-4 rounded-lg">
                  <div className="w-8 h-8 rounded bg-[#27272a] border border-[#3f3f46] text-indigo-400 flex items-center justify-center font-bold text-xs mb-2">01</div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-white">YAML Manifest Parser</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Client passes manifest content to backend. The backend routes write temporary manifests and call the python scanner. The parser evaluates the inputs via PyYAML's safe loaders.
                  </p>
                </div>

                <div className="flex flex-col gap-2 bg-[#09090b]/50 border border-[#27272a] p-4 rounded-lg">
                  <div className="w-8 h-8 rounded bg-[#27272a] border border-[#3f3f46] text-indigo-400 flex items-center justify-center font-bold text-xs mb-2">02</div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-white">Vulnerability Scanning Engine</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Evaluates multi-document manifests against security profiles: checks host namespace sharing, privileged containers, root escalations, writable file assets, tag pins, and memory limits.
                  </p>
                </div>

                <div className="flex flex-col gap-2 bg-[#09090b]/50 border border-[#27272a] p-4 rounded-lg">
                  <div className="w-8 h-8 rounded bg-[#27272a] border border-[#3f3f46] text-indigo-400 flex items-center justify-center font-bold text-xs mb-2">03</div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-white">History Sync & Reporting</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Integrates MongoDB database schemas to record scanned logs. Streams beautiful vector PDF assessment reports directly to the user browser on demand.
                  </p>
                </div>
              </div>

              <div className="bg-[#18181b] border border-[#27272a] p-5 rounded-lg flex flex-col gap-2 mt-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Platform Compliance Policy</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  KubeGuard guidelines align with major industry policies: including the **CISA Kubernetes Hardening Guide**, **NSA Security Guidance**, and the **CIS Kubernetes Benchmark Profiles**. Hardening configs reduces workloads exploit surface areas by 80%.
                </p>
              </div>

              {/* Development Team */}
              <div className="border-t border-[#27272a] pt-5 mt-3">
                <div className="border-b border-[#27272a] pb-3">
                  <h2 className="text-sm font-bold uppercase tracking-wider text-white">Project Development Team</h2>
                  <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mt-0.5">The developers behind the KubeGuard platform</p>
                </div>

                <div className="grid md:grid-cols-2 gap-8 mt-6 justify-items-center">
                  
                  {/* Pradeep Gurjar Profile Card */}
                  <div className="saas-card rounded-xl p-6 flex flex-col items-center max-w-sm w-full border border-[#27272a] bg-[#18181b] hover:border-indigo-500/50 hover:scale-[1.02] transition duration-300 shadow-xl">
                    <div className="w-28 h-28 rounded-full border-2 border-emerald-500/80 overflow-hidden shadow-lg shadow-emerald-500/5 flex items-center justify-center bg-[#09090b]">
                      <img src="/pradeep.png" alt="Pradeep Gurjar" className="w-full h-full object-cover" />
                    </div>
                    <h3 className="text-base font-extrabold text-emerald-400 mt-4 uppercase tracking-wider text-center">Pradeep Gurjar</h3>
                    <p className="text-xs text-slate-300 text-center mt-2 font-medium tracking-wide">
                      Cyber Security Student
                    </p>
                    <span className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mt-1 text-center bg-[#09090b] px-2.5 py-1 rounded border border-[#27272a]">
                      SOC & Cloud Security Enthusiast
                    </span>
                  </div>

                  {/* Ankit Kumar Gurjar Profile Card */}
                  <div className="saas-card rounded-xl p-6 flex flex-col items-center max-w-sm w-full border border-[#27272a] bg-[#18181b] hover:border-indigo-500/50 hover:scale-[1.02] transition duration-300 shadow-xl">
                    <div className="w-28 h-28 rounded-full border-2 border-emerald-500/80 overflow-hidden shadow-lg shadow-emerald-500/5 flex items-center justify-center bg-[#09090b]">
                      <img src="/ankit.png" alt="Ankit Kumar Gurjar" className="w-full h-full object-cover animate-fade-in" />
                    </div>
                    <h3 className="text-base font-extrabold text-emerald-400 mt-4 uppercase tracking-wider text-center">Ankit Kumar Gurjar</h3>
                    <p className="text-xs text-slate-300 text-center mt-2 font-medium tracking-wide">
                      Cyber Security Student
                    </p>
                    <span className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mt-1 text-center bg-[#09090b] px-2.5 py-1 rounded border border-[#27272a]">
                      SOC & Cloud Security Enthusiast
                    </span>
                  </div>

                </div>
              </div>
            </div>
          )}

        </div>

      </div>

      <footer className="border-t border-[#27272a] bg-[#18181b] py-5 text-center text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-auto flex flex-col sm:flex-row items-center justify-between px-6 gap-3">
        <span>KubeGuard platform &copy; {new Date().getFullYear()} • Secure by Design</span>
        <a 
          href="https://github.com/Ankit-Kumar00" 
          target="_blank" 
          rel="noopener noreferrer"
          className="text-indigo-400 hover:text-indigo-300 transition flex items-center gap-1.5 normal-case tracking-normal text-xs"
        >
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
          </svg>
          Developed by Ankit-Kumar00
        </a>
      </footer>
    </div>
  );
}
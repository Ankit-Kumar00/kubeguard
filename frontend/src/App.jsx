import { useState, useEffect } from "react";
import { scanYaml, generateReport } from "./services/api";

function getSeverity(issue) {
  if (issue.includes("Critical")) return "Critical";
  if (issue.includes("High")) return "High";
  return "Medium";
}

export default function App() {
  const [file, setFile] = useState(null);
  const [findings, setFindings] = useState([]);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const saved = localStorage.getItem("kubeguard-history");
    if (saved) setHistory(JSON.parse(saved));
  }, []);

  const handleScan = async () => {
    if (!file) return alert("Upload YAML file first");

    const data = await scanYaml(file);
    const issues = (data.result || "")
      .split("\n")
      .filter(line => line.trim().startsWith("-"));

    setFindings(issues);

    const newScan = {
      fileName: file.name,
      findings: issues,
      scannedAt: new Date().toLocaleString()
    };

    const updated = [newScan, ...history];
    setHistory(updated);
    localStorage.setItem("kubeguard-history", JSON.stringify(updated));
  };

  const critical = findings.filter(i => i.includes("Critical")).length;
  const high = findings.filter(i => i.includes("High")).length;
  const score = Math.max(100 - critical * 30 - high * 15, 0);

  return (
    <div className="min-h-screen bg-slate-950 text-white p-8">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-4xl font-bold">🛡️ KubeGuard</h1>
        <p className="text-slate-400 mt-2">Kubernetes Security Posture Assessment Platform</p>

        <div className="grid md:grid-cols-4 gap-5 mt-8">
          <div className="bg-slate-900 p-5 rounded-xl"><p>Total Issues</p><h2 className="text-3xl font-bold">{findings.length}</h2></div>
          <div className="bg-red-900 p-5 rounded-xl"><p>Critical</p><h2 className="text-3xl font-bold">{critical}</h2></div>
          <div className="bg-orange-900 p-5 rounded-xl"><p>High</p><h2 className="text-3xl font-bold">{high}</h2></div>
          <div className="bg-green-900 p-5 rounded-xl"><p>Security Score</p><h2 className="text-3xl font-bold">{score}/100</h2></div>
        </div>

        <div className="bg-slate-900 rounded-xl p-6 mt-8">
          <h2 className="text-xl font-bold">YAML Security Scanner</h2>
          <input className="mt-5" type="file" accept=".yaml,.yml" onChange={e=>setFile(e.target.files[0])}/>
          <br />
          <button onClick={handleScan} className="mt-5 bg-blue-600 px-6 py-2 rounded-lg">Start Security Scan</button>
        </div>

        <div className="mt-8">
          <h2 className="text-2xl font-bold">Security Findings</h2>
          <button onClick={()=>generateReport(findings)} className="mt-5 bg-green-600 px-6 py-2 rounded-lg">Generate Security Report PDF</button>

          <div className="grid gap-4 mt-4">
            {findings.map((item,index)=>(
              <div key={index} className="bg-slate-900 p-5 rounded-xl border border-slate-700">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold">Security Issue</h3>
                  <span className={`px-3 py-1 rounded-full text-sm ${getSeverity(item)==="Critical"?"bg-red-600":"bg-orange-600"}`}>{getSeverity(item)}</span>
                </div>
                <p className="mt-3 text-slate-300">{item.replace("- ","")}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-10">
          <h2 className="text-2xl font-bold">Scan History</h2>
          {history.map((scan,index)=>(
            <div key={index} className="bg-slate-900 p-4 rounded-xl mt-3 border border-slate-700">
              <p><b>File:</b> {scan.fileName}</p>
              <p><b>Date:</b> {scan.scannedAt}</p>
              <p><b>Issues:</b> {scan.findings.length}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
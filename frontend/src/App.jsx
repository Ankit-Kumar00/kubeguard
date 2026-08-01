import { useEffect, useState } from "react";
import { checkAPI } from "./services/api";

function App() {

  const [status, setStatus] = useState("");

  useEffect(() => {
    checkAPI()
      .then((data) => {
        setStatus(data.message);
      })
      .catch(() => {
        setStatus("Backend not connected");
      });
  }, []);

  return (
    <div>
      <h1>KubeGuard 🛡️</h1>
      <h2>Kubernetes Security Posture Assessment Platform</h2>

      <div>
        <h3>System Status</h3>
        <p>{status}</p>
      </div>

      <div>
        <h3>Security Modules</h3>
        <ul>
          <li>YAML Security Scanner</li>
          <li>Container Vulnerability Scanner</li>
          <li>Kubernetes Audit Logs</li>
          <li>Security Reports</li>
        </ul>
      </div>
    </div>
  );
}

export default App;
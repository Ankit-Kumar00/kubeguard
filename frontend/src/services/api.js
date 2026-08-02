const API_URL = "https://kubeguard.onrender.com/api";

// Scan YAML file or pasted text
export async function scanYaml(source, fileName = "pasted_manifest.yaml") {
  let response;

  if (source instanceof File) {
    const formData = new FormData();
    formData.append("file", source);

    response = await fetch(`${API_URL}/scan-yaml`, {
      method: "POST",
      body: formData,
    });
  } else {
    // Pasted text
    response = await fetch(`${API_URL}/scan-yaml`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        yaml: source,
        fileName: fileName,
      }),
    });
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || "Security scan failed");
  }

  return await response.json();
}

// Generate PDF Report
export async function generateReport(reportData) {
  const response = await fetch(`${API_URL}/generate-report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reportData),
  });

  if (!response.ok) {
    throw new Error("PDF generation failed");
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `KubeGuard_Report_${reportData.fileName || "manifest"}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  window.URL.revokeObjectURL(url);
}

// Fetch saved scan history from backend
export async function fetchHistory() {
  const response = await fetch(`${API_URL}/history`);
  if (!response.ok) {
    throw new Error("Failed to load scan history");
  }
  return await response.json();
}

// Delete scan report by ID
export async function deleteHistoryItem(id) {
  const response = await fetch(`${API_URL}/history/${id}`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error("Failed to delete scan report");
  }
  return await response.json();
}
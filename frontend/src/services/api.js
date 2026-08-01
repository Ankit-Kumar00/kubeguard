const API_URL = "http://localhost:5000/api";


export async function scanYaml(file) {

    const formData = new FormData();

    formData.append("file", file);


    const response = await fetch(
        `${API_URL}/scan-yaml`,
        {
            method: "POST",
            body: formData
        }
    );


    return await response.json();

}export async function generateReport(findings){

    const response = await fetch(
        "http://localhost:5000/api/generate-report",
        {
            method:"POST",
            headers:{
                "Content-Type":"application/json"
            },
            body:JSON.stringify({
                findings:findings
            })
        }
    );


    const blob = await response.blob();


    const url = window.URL.createObjectURL(blob);


    const a = document.createElement("a");

    a.href=url;

    a.download="KubeGuard_Report.pdf";

    a.click();

}
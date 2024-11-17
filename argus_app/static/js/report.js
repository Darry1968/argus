document.getElementById('generate-report').addEventListener('click', () => {
    const selectedScan = document.getElementById('scan-select').value;

    fetch(`/report?scan=${selectedScan}`)
        .then(response => response.json())
        .then(data => {
            const reportOutput = document.getElementById('report-output');
            reportOutput.innerHTML = `
                <pre>${JSON.stringify(data, null, 2)}</pre>
                <a href="/download?scan=${selectedScan}" download>Download Report</a>
            `;
        })
        .catch(err => {
            alert('Failed to generate report: ' + err.message);
        });
});

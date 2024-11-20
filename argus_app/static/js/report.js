document.addEventListener("DOMContentLoaded", () => {
    const reportForm = document.getElementById("report-form");
    const scanSelect = document.getElementById("scan-select");
    const generateReportButton = document.getElementById("generate-report");

    reportForm.addEventListener("submit", (event) => {
        event.preventDefault(); // Prevent form submission

        const selectedScanId = scanSelect.value;
        if (!selectedScanId) {
            alert("Please select a scan.");
            return;
        }

        // Construct the report generation URL dynamically
        const reportUrl = `/generate-report/${selectedScanId}`;
        generateReportButton.href = reportUrl;

        // Trigger the download
        window.location.href = reportUrl;
    });
});

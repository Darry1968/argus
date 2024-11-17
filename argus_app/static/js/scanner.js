document.getElementById('run-scan-web').addEventListener('click', () => {
    const endpoint = document.getElementById('api-endpoint').value;
    if (!endpoint) {
        alert('Please enter a valid API endpoint!');
        return;
    }

    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoint }),
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('results-output').innerText = JSON.stringify(data, null, 2);
    })
    .catch(err => {
        document.getElementById('results-output').innerText = 'Error: ' + err.message;
    });
});

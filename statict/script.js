document.getElementById('scanBtn').addEventListener('click', function() {
    const url = document.getElementById('targetUrl').value;
    if (!url) return alert("URL을 입력하세요!");

    document.getElementById('loading').style.display = 'block';
    document.getElementById('resultTable').style.display = 'none';
    document.getElementById('safeMsg').style.display = 'none';
    document.getElementById('resultBody').innerHTML = '';

    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById('loading').style.display = 'none';
        
        if (data.results && data.results.length > 0) {
            document.getElementById('resultTable').style.display = 'table';
            data.results.forEach(vuln => {
                document.getElementById('resultBody').innerHTML += `
                    <tr>
                        <td class="text-danger fw-bold">${vuln.name}</td>
                        <td>${vuln.url}</td>
                        <td><code>${vuln.payload}</code></td>
                        <td><span class="badge bg-warning text-dark">${vuln.word}</span></td>
                    </tr>
                `;
            });
        } else {
            document.getElementById('safeMsg').style.display = 'block';
        }
    })
    .catch(err => {
        document.getElementById('loading').style.display = 'none';
        alert("스캔 중 오류가 발생했습니다.");
    });
});
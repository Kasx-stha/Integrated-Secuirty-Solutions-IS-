const masterToggleBtn = document.getElementById('masterToggle');
const graylogBtn = document.getElementById('graylogBtn');
const reportBtn = document.getElementById('reportBtn');
const downloadReportBtn = document.getElementById('downloadReportBtn');
const systemToggles = document.querySelectorAll('.system-toggle');
const toast = document.getElementById('toast');

// Configuration
const API_ENDPOINT = 'http://192.168.196.128:5000/api';
const GRAYLOG_URL = 'http://192.168.196.128:9000';

// Systems configuration
const systems = [
    { type: 'ids', name: 'Network IDS' },
    { type: 'ips', name: 'Host IPS' },
    { type: 'honeypot', name: 'Honeypot' }
];

// Helper Functions
function showToast(message, duration = 3000) {
    toast.textContent = message;
    toast.style.display = 'block';
    setTimeout(() => {
        toast.style.display = 'none';
    }, duration);
}

function updateSystemUI(systemElement, isActive) {
    const statusBadge = systemElement.querySelector('.status-badge');
    const statusText = systemElement.querySelector('.status-text');
    const toggle = systemElement.querySelector('.system-toggle');

    statusBadge.textContent = isActive ? 'ACTIVE' : 'INACTIVE';
    statusBadge.classList.toggle('active', isActive);
    statusText.textContent = isActive ? 'System Active' : 'System Inactive';
    toggle.checked = isActive;
}

// Master toggle event handler
masterToggleBtn.addEventListener('click', async () => {
    const btnText = masterToggleBtn.querySelector('.text');
    const originalText = btnText.textContent;
    masterToggleBtn.disabled = true;
    btnText.textContent = 'Activating Systems...';

    try {
        const response = await fetch(`${API_ENDPOINT}/start-systems`, { method: 'POST' });
        const result = await response.json();

        if (result.success) {
            showToast('All security systems activated successfully');
            systems.forEach(system => {
                const systemElement = document.querySelector(`[data-system="${system.type}"]`);
                updateSystemUI(systemElement, true);
            });
        } else {
            showToast(`Activation failed: ${result.error}`);
        }
    } catch (error) {
        console.error('Activation error:', error);
        showToast('Error activating systems');
    } finally {
        btnText.textContent = originalText;
        masterToggleBtn.disabled = false;
    }
});

// Graylog integration
graylogBtn.addEventListener('click', () => {
    window.open(GRAYLOG_URL, '_blank');
});

// Report download button handler
downloadReportBtn.addEventListener('click', async () => {
    downloadReportBtn.disabled = true;
    const originalText = downloadReportBtn.textContent;
    downloadReportBtn.textContent = 'Downloading Report...';

    try {
        const response = await fetch(`${API_ENDPOINT}/download-latest-report`);

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);

            // Generate the filename dynamically
            const today = new Date();
            const year = today.getFullYear();
            const month = String(today.getMonth() + 1).padStart(2, '0'); // Ensure two digits
            const day = String(today.getDate()).padStart(2, '0'); // Ensure two digits
            const filename = `Integrated_Security_Daily_Report_${year}${month}${day}.pdf`;

            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);

            showToast('Report downloaded successfully');
        } else {
            showToast('Failed to download report');
        }
    } catch (error) {
        console.error('Download error:', error);
        showToast('Error downloading report');
    } finally {
        downloadReportBtn.textContent = originalText;
        downloadReportBtn.disabled = false;
    }
});

// Graylog integration
graylogBtn.addEventListener('click', () => {
    window.open(GRAYLOG_URL, '_blank');
});

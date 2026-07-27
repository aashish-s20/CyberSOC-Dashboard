document.addEventListener('DOMContentLoaded', function () {
    // Sidebar toggle functionality
    const sidebarCollapse = document.getElementById('sidebarCollapse');
    const sidebar = document.getElementById('sidebar');

    if (sidebarCollapse && sidebar) {
        sidebarCollapse.addEventListener('click', function () {
            sidebar.classList.toggle('active');
        });
    }

    // Auto-dismiss alert boxes after 5 seconds
    const alerts = document.querySelectorAll('.alert-custom');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            let bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Color definitions matching the CSS variable system
    const chartColors = {
        blue: '#3b82f6',
        blueGlow: 'rgba(59, 130, 246, 0.1)',
        cyan: '#06b6d4',
        cyanGlow: 'rgba(6, 182, 212, 0.1)',
        grid: 'rgba(255, 255, 255, 0.05)',
        text: '#9ca3af',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#10b981'
    };

    // 1. Security Events (Weekly Trend) Chart
    const secEventsCtx = document.getElementById('securityEventsChart');
    if (secEventsCtx) {
        new Chart(secEventsCtx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Security Events Logged',
                    data: [142, 219, 133, 405, 232, 123, 90],
                    borderColor: chartColors.blue,
                    backgroundColor: chartColors.blueGlow,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointBackgroundColor: chartColors.blue,
                    pointBorderColor: '#fff',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text, font: { family: 'Inter' } } },
                    y: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text, font: { family: 'Inter' } } }
                }
            }
        });
    }

    // 2. Network Activity (Throughput) Chart
    const netActivityCtx = document.getElementById('networkActivityChart');
    if (netActivityCtx) {
        new Chart(netActivityCtx, {
            type: 'line',
            data: {
                labels: ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00'],
                datasets: [{
                    label: 'Traffic Vol (Gbps)',
                    data: [45, 68, 92, 54, 76, 89],
                    borderColor: chartColors.cyan,
                    backgroundColor: chartColors.cyanGlow,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: chartColors.cyan,
                    pointBorderColor: '#fff',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text, font: { family: 'Inter' } } },
                    y: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text, font: { family: 'Inter' } } }
                }
            }
        });
    }

    // 3. Incident Overview (Severity Breakdown) Chart
    const incidentOverviewCtx = document.getElementById('incidentOverviewChart');
    if (incidentOverviewCtx) {
        new Chart(incidentOverviewCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [3, 8, 24, 65],
                    backgroundColor: [
                        chartColors.danger,
                        chartColors.warning,
                        chartColors.blue,
                        chartColors.success
                    ],
                    borderColor: '#121826',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: chartColors.text,
                            font: { family: 'Inter', size: 11 }
                        }
                    }
                }
            }
        });
    }

    // 4. Threat Distribution (Radar) Chart
    const threatDistributionCtx = document.getElementById('threatDistributionChart');
    if (threatDistributionCtx) {
        new Chart(threatDistributionCtx, {
            type: 'radar',
            data: {
                labels: ['Malware', 'Phishing', 'Intrusion', 'Brute Force', 'DDoS'],
                datasets: [{
                    label: 'Threat Vector Severity',
                    data: [65, 59, 90, 81, 56],
                    borderColor: chartColors.blue,
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    borderWidth: 2,
                    pointBackgroundColor: chartColors.cyan,
                    pointBorderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    r: {
                        angleLines: { color: 'rgba(255, 255, 255, 0.08)' },
                        grid: { color: 'rgba(255, 255, 255, 0.08)' },
                        pointLabels: {
                            color: chartColors.text,
                            font: { family: 'Inter', size: 11 }
                        },
                        ticks: {
                            backdropColor: 'transparent',
                            color: chartColors.text,
                            font: { family: 'Inter', size: 8 }
                        }
                    }
                }
            }
        });
    }
});

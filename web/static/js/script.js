// Global JavaScript functions for the web interface

// Function to format dates
function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Function to get severity class
function getSeverityClass(description) {
    if (!description) return '';
    const desc = description.toLowerCase();
    if (desc.includes('critical')) return 'critical';
    if (desc.includes('high')) return 'high';
    if (desc.includes('medium')) return 'medium';
    if (desc.includes('low')) return 'low';
    return '';
}

// Function to get severity text
function getSeverityText(description) {
    if (!description) return 'Unknown';
    const desc = description.toLowerCase();
    if (desc.includes('critical')) return 'Critical';
    if (desc.includes('high')) return 'High';
    if (desc.includes('medium')) return 'Medium';
    if (desc.includes('low')) return 'Low';
    return 'Unknown';
}

// Function to export results
function exportResults(format) {
    alert('Export as ' + format.toUpperCase() + ' would be implemented in a full version');
}

// Function to print results
function printResults() {
    window.print();
}

// Function to update statistics
function updateStats() {
    // This function can be overridden by page-specific implementations
    console.log('Updating statistics...');
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Web interface loaded');
    updateStats();
});
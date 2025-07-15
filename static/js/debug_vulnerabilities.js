// Debug script to test vulnerability display
// Run this in browser console on scan detail page

async function debugVulnerabilities(scanId) {
    console.log('🔍 DEBUG: Testing vulnerability display for scan:', scanId);
    
    try {
        // Test API call
        const response = await fetch(`/api/scan/${scanId}/detailed`);
        const data = await response.json();
        
        console.log('🔍 DEBUG: API Response:', data);
        console.log('🔍 DEBUG: API Success:', data.success);
        console.log('🔍 DEBUG: API Status:', data.data?.status);
        console.log('🔍 DEBUG: Results exists:', !!data.data?.results);
        console.log('🔍 DEBUG: Vulnerabilities exist:', !!data.data?.results?.vulnerabilities);
        console.log('🔍 DEBUG: Vulnerabilities count:', data.data?.results?.vulnerabilities?.length || 0);
        
        if (data.data?.results?.vulnerabilities) {
            console.log('🔍 DEBUG: First vulnerability:', data.data.results.vulnerabilities[0]);
        }
        
        // Test the container
        const container = document.getElementById('vulnerabilitiesDetails');
        console.log('🔍 DEBUG: Container found:', !!container);
        console.log('🔍 DEBUG: Container current content:', container?.innerHTML);
        
        // Test the display function directly
        if (typeof displayDetailedVulnerabilities === 'function') {
            console.log('🔍 DEBUG: displayDetailedVulnerabilities function exists');
            if (data.data?.results?.vulnerabilities) {
                console.log('🔍 DEBUG: Calling displayDetailedVulnerabilities with', data.data.results.vulnerabilities.length, 'vulnerabilities');
                displayDetailedVulnerabilities(data.data.results.vulnerabilities);
            } else {
                console.log('🔍 DEBUG: No vulnerabilities to display');
            }
        } else {
            console.log('🔍 DEBUG: displayDetailedVulnerabilities function NOT found!');
        }
        
        return data;
    } catch (error) {
        console.error('🔍 DEBUG: Error testing vulnerabilities:', error);
        return null;
    }
}

// Test with current scan ID (replace with actual scan ID)
// debugVulnerabilities('9fba08d9-51e0-413c-a53e-7d85d5c3b404');

console.log('🔍 DEBUG: Debug script loaded. Run debugVulnerabilities("your-scan-id") to test.'); 
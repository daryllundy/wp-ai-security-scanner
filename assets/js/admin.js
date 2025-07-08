jQuery(document).ready(function($) {
    'use strict';
    
    // Scan control functionality
    let scanInterval;
    let isScanning = false;
    
    // Start scan button
    $('#start-scan').on('click', function(e) {
        e.preventDefault();
        startScan();
    });
    
    // Quick scan button
    $('#quick-scan').on('click', function(e) {
        e.preventDefault();
        startScan(true);
    });
    
    // Cancel scan button
    $('#cancel-scan').on('click', function(e) {
        e.preventDefault();
        cancelScan();
    });
    
    // Threat action buttons
    $(document).on('click', '.view-details', function(e) {
        e.preventDefault();
        const threatId = $(this).data('id');
        viewThreatDetails(threatId);
    });
    
    $(document).on('click', '.quarantine-file', function(e) {
        e.preventDefault();
        const threatId = $(this).data('id');
        quarantineFile(threatId);
    });
    
    $(document).on('click', '.ignore-threat', function(e) {
        e.preventDefault();
        const threatId = $(this).data('id');
        ignoreThreat(threatId);
    });
    
    function startScan(quickScan = false) {
        if (isScanning) {
            return;
        }
        
        isScanning = true;
        
        // Update UI
        $('#start-scan, #quick-scan').prop('disabled', true);
        $('.scan-actions').html(`
            <div class="scan-progress">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <p>Initializing scan...</p>
                <button type="button" class="button" id="cancel-scan">Cancel Scan</button>
            </div>
        `);
        
        // Start scan via AJAX
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'start_scan',
                nonce: wpAiScannerAjax.nonce,
                quick_scan: quickScan
            },
            success: function(response) {
                if (response.success) {
                    // Start polling for progress
                    scanInterval = setInterval(updateScanProgress, 2000);
                } else {
                    showError('Failed to start scan: ' + response.data);
                    resetScanUI();
                }
            },
            error: function(xhr, status, error) {
                showError('Error starting scan: ' + error);
                resetScanUI();
            }
        });
    }
    
    function updateScanProgress() {
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'get_scan_progress',
                nonce: wpAiScannerAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    const progress = response.data;
                    
                    // Update progress bar
                    $('.progress-fill').css('width', progress.percentage + '%');
                    
                    // Update status text
                    let statusText = `Scanning... ${progress.percentage}%`;
                    if (progress.current_file) {
                        statusText += ` (${getBasename(progress.current_file)})`;
                    }
                    if (progress.estimated_time > 0) {
                        statusText += ` - ${formatTime(progress.estimated_time)} remaining`;
                    }
                    
                    $('.scan-progress p').text(statusText);
                    
                    // Check if scan is complete
                    if (progress.status === 'completed' || progress.status === 'cancelled' || progress.status === 'error') {
                        clearInterval(scanInterval);
                        
                        if (progress.status === 'completed') {
                            showSuccess(`Scan completed! ${progress.threats_found} threats found.`);
                        } else if (progress.status === 'cancelled') {
                            showInfo('Scan cancelled.');
                        } else {
                            showError('Scan failed: ' + (progress.error_message || 'Unknown error'));
                        }
                        
                        // Reload page after a short delay to show updated results
                        setTimeout(() => {
                            window.location.reload();
                        }, 2000);
                    }
                }
            },
            error: function() {
                // Continue polling even if there's an error
                console.log('Error getting scan progress');
            }
        });
    }
    
    function cancelScan() {
        if (scanInterval) {
            clearInterval(scanInterval);
        }
        
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'cancel_scan',
                nonce: wpAiScannerAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    showInfo('Scan cancelled.');
                } else {
                    showError('Error cancelling scan.');
                }
                resetScanUI();
            },
            error: function() {
                showError('Error cancelling scan.');
                resetScanUI();
            }
        });
    }
    
    function resetScanUI() {
        isScanning = false;
        
        $('.scan-actions').html(`
            <button type="button" class="button button-primary" id="start-scan">Start Full Scan</button>
            <button type="button" class="button" id="quick-scan">Quick Scan</button>
        `);
        
        // Re-bind event handlers
        $('#start-scan').on('click', function(e) {
            e.preventDefault();
            startScan();
        });
        
        $('#quick-scan').on('click', function(e) {
            e.preventDefault();
            startScan(true);
        });
    }
    
    function viewThreatDetails(threatId) {
        // Create modal or expand row to show threat details
        // This would typically show file content, line numbers, etc.
        alert('Viewing threat details for ID: ' + threatId);
    }
    
    function quarantineFile(threatId) {
        if (!confirm('Are you sure you want to quarantine this file? This will move it to a safe location.')) {
            return;
        }
        
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'quarantine_file',
                nonce: wpAiScannerAjax.nonce,
                threat_id: threatId
            },
            success: function(response) {
                if (response.success) {
                    showSuccess('File quarantined successfully.');
                    // Update the row to show quarantined status
                    location.reload();
                } else {
                    showError('Error quarantining file: ' + response.data);
                }
            },
            error: function() {
                showError('Error quarantining file.');
            }
        });
    }
    
    function ignoreThreat(threatId) {
        if (!confirm('Are you sure you want to ignore this threat? It will be marked as a false positive.')) {
            return;
        }
        
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'ignore_threat',
                nonce: wpAiScannerAjax.nonce,
                threat_id: threatId
            },
            success: function(response) {
                if (response.success) {
                    showSuccess('Threat ignored successfully.');
                    // Update the row to show ignored status
                    location.reload();
                } else {
                    showError('Error ignoring threat: ' + response.data);
                }
            },
            error: function() {
                showError('Error ignoring threat.');
            }
        });
    }
    
    // Utility functions
    function getBasename(path) {
        return path.split('/').pop();
    }
    
    function formatTime(seconds) {
        if (seconds < 60) {
            return seconds + 's';
        } else if (seconds < 3600) {
            return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
        } else {
            return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
        }
    }
    
    function showSuccess(message) {
        showNotice(message, 'success');
    }
    
    function showError(message) {
        showNotice(message, 'error');
    }
    
    function showInfo(message) {
        showNotice(message, 'info');
    }
    
    function showNotice(message, type = 'info') {
        const notice = $(`
            <div class="notice notice-${type} is-dismissible">
                <p>${message}</p>
                <button type="button" class="notice-dismiss">
                    <span class="screen-reader-text">Dismiss this notice.</span>
                </button>
            </div>
        `);
        
        $('.wrap h1').after(notice);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            notice.fadeOut();
        }, 5000);
        
        // Handle manual dismiss
        notice.find('.notice-dismiss').on('click', function() {
            notice.fadeOut();
        });
    }
    
    // Auto-refresh threat counts every 30 seconds
    setInterval(function() {
        if (!isScanning) {
            refreshThreatCounts();
        }
    }, 30000);
    
    // API key testing functionality
    $('#test-openai-key').on('click', function(e) {
        e.preventDefault();
        testApiKey('openai');
    });
    
    $('#test-virustotal-key').on('click', function(e) {
        e.preventDefault();
        testApiKey('virustotal');
    });
    
    function refreshThreatCounts() {
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'get_threat_stats',
                nonce: wpAiScannerAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    const stats = response.data;
                    
                    // Update threat counts
                    $('.threat-count.critical .count').text(stats.critical_threats);
                    $('.threat-count.high .count').text(stats.high_threats);
                    $('.threat-count.medium .count').text(stats.medium_threats);
                    $('.threat-count.low .count').text(stats.low_threats);
                    
                    // Update security status
                    const statusIndicator = $('.status-indicator');
                    statusIndicator.removeClass('safe warning critical');
                    
                    if (stats.critical_threats > 0) {
                        statusIndicator.addClass('critical');
                        statusIndicator.find('strong').text('Critical Threats Detected');
                        statusIndicator.find('.dashicons').removeClass('dashicons-shield dashicons-info').addClass('dashicons-warning');
                    } else if (stats.high_threats > 0) {
                        statusIndicator.addClass('warning');
                        statusIndicator.find('strong').text('High Priority Threats');
                        statusIndicator.find('.dashicons').removeClass('dashicons-shield dashicons-warning').addClass('dashicons-info');
                    } else {
                        statusIndicator.addClass('safe');
                        statusIndicator.find('strong').text('System Secure');
                        statusIndicator.find('.dashicons').removeClass('dashicons-warning dashicons-info').addClass('dashicons-shield');
                    }
                }
            },
            error: function() {
                console.log('Error refreshing threat counts');
            }
        });
    }
    
    function testApiKey(provider) {
        const button = $('#test-' + provider + '-key');
        const result = $('#' + provider + '-test-result');
        const apiKey = $('input[name="' + provider + '_api_key"]').val();
        
        if (!apiKey) {
            result.html('<span style="color: #d63638;">Please enter an API key first</span>');
            return;
        }
        
        button.prop('disabled', true).text('Testing...');
        result.html('<span style="color: #0073aa;">Testing API key...</span>');
        
        $.ajax({
            url: wpAiScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'test_' + provider + '_key',
                nonce: wpAiScannerAjax.nonce,
                api_key: apiKey
            },
            success: function(response) {
                if (response.success) {
                    result.html('<span style="color: #00a32a;">✓ ' + response.data + '</span>');
                } else {
                    result.html('<span style="color: #d63638;">✗ ' + response.data + '</span>');
                }
            },
            error: function() {
                result.html('<span style="color: #d63638;">✗ Connection error</span>');
            },
            complete: function() {
                button.prop('disabled', false).text('Test API Key');
            }
        });
    }
});
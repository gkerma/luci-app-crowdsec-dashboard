'use strict';
'require rpc';
'require baseclass';

/**
 * CrowdSec Dashboard API Module
 * Provides interface to CrowdSec RPCD backend
 * Copyright (C) 2024 CyberMind.fr - Gandalf
 */

var callCrowdsecDecisions = rpc.declare({
	object: 'crowdsec',
	method: 'decisions',
	expect: { '': [] }
});

var callCrowdsecAlerts = rpc.declare({
	object: 'crowdsec',
	method: 'alerts',
	params: ['limit'],
	expect: { '': [] }
});

var callCrowdsecMetrics = rpc.declare({
	object: 'crowdsec',
	method: 'metrics',
	expect: { '': {} }
});

var callCrowdsecBouncers = rpc.declare({
	object: 'crowdsec',
	method: 'bouncers',
	expect: { '': [] }
});

var callCrowdsecMachines = rpc.declare({
	object: 'crowdsec',
	method: 'machines',
	expect: { '': [] }
});

var callCrowdsecHub = rpc.declare({
	object: 'crowdsec',
	method: 'hub',
	expect: { '': {} }
});

var callCrowdsecStatus = rpc.declare({
	object: 'crowdsec',
	method: 'status',
	expect: { '': {} }
});

var callCrowdsecStats = rpc.declare({
	object: 'crowdsec',
	method: 'stats',
	expect: { '': {} }
});

var callCrowdsecBan = rpc.declare({
	object: 'crowdsec',
	method: 'ban',
	params: ['ip', 'duration', 'reason'],
	expect: { success: false }
});

var callCrowdsecUnban = rpc.declare({
	object: 'crowdsec',
	method: 'unban',
	params: ['ip'],
	expect: { success: false }
});

return baseclass.extend({
	/**
	 * Get all active decisions (bans)
	 */
	getDecisions: function() {
		return callCrowdsecDecisions().then(function(data) {
			return Array.isArray(data) ? data : [];
		}).catch(function() {
			return [];
		});
	},

	/**
	 * Get alerts with optional limit
	 */
	getAlerts: function(limit) {
		return callCrowdsecAlerts(limit || 50).then(function(data) {
			return Array.isArray(data) ? data : [];
		}).catch(function() {
			return [];
		});
	},

	/**
	 * Get metrics from CrowdSec
	 */
	getMetrics: function() {
		return callCrowdsecMetrics().catch(function() {
			return {};
		});
	},

	/**
	 * Get registered bouncers
	 */
	getBouncers: function() {
		return callCrowdsecBouncers().then(function(data) {
			return Array.isArray(data) ? data : [];
		}).catch(function() {
			return [];
		});
	},

	/**
	 * Get registered machines
	 */
	getMachines: function() {
		return callCrowdsecMachines().then(function(data) {
			return Array.isArray(data) ? data : [];
		}).catch(function() {
			return [];
		});
	},

	/**
	 * Get hub status (collections, parsers, scenarios)
	 */
	getHub: function() {
		return callCrowdsecHub().catch(function() {
			return {};
		});
	},

	/**
	 * Get service status
	 */
	getStatus: function() {
		return callCrowdsecStatus().catch(function() {
			return { crowdsec: 'unknown', bouncer: 'unknown', version: 'unknown' };
		});
	},

	/**
	 * Get dashboard statistics
	 */
	getStats: function() {
		return callCrowdsecStats().catch(function() {
			return { total_decisions: 0, alerts_24h: 0, bouncers: 0 };
		});
	},

	/**
	 * Ban an IP address
	 */
	banIP: function(ip, duration, reason) {
		return callCrowdsecBan(ip, duration || '4h', reason || 'Manual ban from dashboard');
	},

	/**
	 * Unban an IP address
	 */
	unbanIP: function(ip) {
		return callCrowdsecUnban(ip);
	},

	/**
	 * Get all data for dashboard overview
	 */
	getDashboardData: function() {
		var self = this;
		return Promise.all([
			self.getStatus(),
			self.getStats(),
			self.getDecisions(),
			self.getAlerts(20),
			self.getBouncers()
		]).then(function(results) {
			return {
				status: results[0],
				stats: results[1],
				decisions: results[2],
				alerts: results[3],
				bouncers: results[4]
			};
		});
	},

	/**
	 * Format relative time
	 */
	formatRelativeTime: function(timestamp) {
		if (!timestamp) return 'N/A';
		
		var now = new Date();
		var date = new Date(timestamp);
		var diff = Math.floor((now - date) / 1000);
		
		if (diff < 60) return diff + 's ago';
		if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
		if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
		return Math.floor(diff / 86400) + 'd ago';
	},

	/**
	 * Format duration string
	 */
	formatDuration: function(duration) {
		if (!duration) return 'N/A';
		
		// Parse Go duration format (e.g., "3h59m59.123456789s")
		var match = duration.match(/(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?/);
		if (!match) return duration;
		
		var hours = parseInt(match[1]) || 0;
		var minutes = parseInt(match[2]) || 0;
		var seconds = Math.floor(parseFloat(match[3])) || 0;
		
		var parts = [];
		if (hours > 0) parts.push(hours + 'h');
		if (minutes > 0) parts.push(minutes + 'm');
		if (seconds > 0 && hours === 0) parts.push(seconds + 's');
		
		return parts.length > 0 ? parts.join(' ') : '< 1s';
	},

	/**
	 * Get country flag emoji from country code
	 */
	getCountryFlag: function(countryCode) {
		if (!countryCode || countryCode.length !== 2) return '🌍';
		
		var code = countryCode.toUpperCase();
		var offset = 127397;
		var flag = String.fromCodePoint(
			code.charCodeAt(0) + offset,
			code.charCodeAt(1) + offset
		);
		return flag;
	},

	/**
	 * Parse scenario name to short form
	 */
	parseScenario: function(scenario) {
		if (!scenario) return 'unknown';
		// crowdsecurity/ssh-bf -> ssh-bf
		var parts = scenario.split('/');
		return parts[parts.length - 1];
	},

	/**
	 * Validate IP address
	 */
	isValidIP: function(ip) {
		// IPv4
		var ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
		// IPv6 (simplified)
		var ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
		
		return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
	}
});

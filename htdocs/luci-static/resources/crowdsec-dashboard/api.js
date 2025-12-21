'use strict';
'require baseclass';
'require rpc';

var callStatus = rpc.declare({
	object: 'luci.crowdsec',
	method: 'status',
	expect: { }
});

var callDecisions = rpc.declare({
	object: 'luci.crowdsec',
	method: 'decisions',
	expect: { decisions: [] }
});

var callAlerts = rpc.declare({
	object: 'luci.crowdsec',
	method: 'alerts',
	expect: { alerts: [] }
});

var callBouncers = rpc.declare({
	object: 'luci.crowdsec',
	method: 'bouncers',
	expect: { bouncers: [] }
});

var callMetrics = rpc.declare({
	object: 'luci.crowdsec',
	method: 'metrics',
	expect: { }
});

return baseclass.extend({
	getStatus: callStatus,
	getDecisions: callDecisions,
	getAlerts: callAlerts,
	getBouncers: callBouncers,
	getMetrics: callMetrics
});

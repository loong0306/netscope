import test from 'node:test';
import assert from 'node:assert/strict';
import { bytes, endpointLabel, filterFlows, groupPeers } from '../web/format.js';

test('unknown rates stay distinct from actual zero', () => {
  assert.equal(bytes(null), '—');
  assert.equal(bytes(0), '0 B');
  assert.equal(bytes(1536), '1.5 KB');
});
test('IPv6 endpoint has unambiguous port delimiters', () => {
  assert.equal(endpointLabel('::1', 443), '[::1]:443');
  assert.equal(endpointLabel('1.1.1.1', null), '1.1.1.1');
});
test('flow search and protocol filters combine, loopback can be hidden', () => {
  const flows = [{remote_ip:'1.1.1.1',local_ip:'10.0.0.2',remote_port:443,process:'Chrome',protocol:'TCP'},
    {remote_ip:'::1',local_ip:'::1',remote_port:53,process:'DNS',protocol:'UDP'}];
  assert.equal(filterFlows(flows, {query:'chrome',protocol:'TCP',hideLoopback:true}).length, 1);
  assert.equal(filterFlows(flows, {query:'chrome',protocol:'UDP'}).length, 0);
  assert.equal(filterFlows(flows, {hideLoopback:true}).length, 1);
});
test('peer aggregation conserves measured bytes and never manufactures unknown rates', () => {
  const peers = groupPeers([{remote_ip:'1.1.1.1',protocol:'TCP',rx_bytes:50,tx_bytes:40,rx_bps:null,tx_bps:null},
    {remote_ip:'1.1.1.1',protocol:'UDP',rx_bytes:100,tx_bytes:10,rx_bps:null,tx_bps:null}]);
  assert.equal(peers.length, 1);
  assert.equal(peers[0].rx_bytes, 150);
  assert.equal(peers[0].rx_bps, null);
  assert.equal(peers[0].count, 2);
});

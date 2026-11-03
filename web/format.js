export function bytes(value, digits = 1) {
  if (value == null || !Number.isFinite(value)) return '—';
  if (value === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.max(0, Math.floor(Math.log(Math.abs(value)) / Math.log(1024))));
  return `${(value / 1024 ** i).toFixed(i ? digits : 0)} ${units[i]}`;
}

export const rate = value => value == null ? '—' : `${bytes(value)}/s`;
export const endpointLabel = (ip, port) => port == null ? ip : `${ip.includes(':') ? `[${ip}]` : ip}:${port}`;
export const loopback = ip => ip === '::1' || ip?.startsWith('127.');
export const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const timeLabel = value => new Date(value * 1000).toLocaleTimeString('zh-CN', {hour12:false});

export function filterFlows(flows, {query = '', protocol = 'ALL', hideLoopback = false, interface: iface} = {}) {
  const search = query.trim().toLowerCase();
  return flows.filter(flow => (!hideLoopback || !loopback(flow.remote_ip))
    && (protocol === 'ALL' || flow.protocol === protocol)
    && (!iface || flow.interface === iface)
    && (!search || [flow.remote_ip, flow.remote_port, flow.local_ip, flow.local_port,
      flow.process, flow.pid, flow.interface, flow.protocol].join(' ').toLowerCase().includes(search)));
}

export function groupPeers(flows) {
  const groups = new Map();
  for (const flow of flows) {
    let peer = groups.get(flow.remote_ip);
    if (!peer) {
      peer = {ip:flow.remote_ip, count:0, flows:[], protocol:flow.protocol,
        rx_bps:null, tx_bps:null, rx_bytes:null, tx_bytes:null, packets:0, captured_bytes:0};
      groups.set(flow.remote_ip, peer);
    }
    peer.count++;
    peer.flows.push(flow);
    peer.packets += flow.packets || 0;
    peer.captured_bytes += flow.captured_bytes || 0;
    for (const key of ['rx_bps','tx_bps','rx_bytes','tx_bytes']) {
      if (flow[key] != null) peer[key] = (peer[key] || 0) + flow[key];
    }
  }
  return [...groups.values()].sort((a,b) => ((b.rx_bps || 0) + (b.tx_bps || 0)) - ((a.rx_bps || 0) + (a.tx_bps || 0)));
}

export const serviceHint = (protocol, port) => ({'TCP:443':'HTTPS / TLS','UDP:443':'QUIC / HTTPS',
  'TCP:80':'HTTP','UDP:53':'DNS','TCP:53':'DNS','TCP:22':'SSH','TCP:993':'IMAPS',
  'TCP:465':'SMTPS','UDP:5353':'mDNS','TCP:5223':'Apple Push'}[`${protocol}:${port}`] || '未知服务');

import {bytes, rate, endpointLabel, loopback, escape as esc, timeLabel, filterFlows, groupPeers, serviceHint} from './format.js';

const $=id=>document.getElementById(id);
let snapshot=null, latest=null, token='', paused=false, tab='connections', selected=null, traceTarget=null;
let filters={query:'',protocol:'ALL',hideLoopback:true};
let topology=null, peers=[], flows=[], lastSample=null, lastSeen=0, toastTimer;
const history={rx:[],tx:[]};
const protocolClass=protocol=>protocol==='UDP'?'udp':protocol?.startsWith('ICMP')?'icmp':'tcp';
const badge=protocol=>`<span class="protocol-badge ${protocolClass(protocol)}">${esc(protocol)}</span>`;

function toast(message){$('toast').textContent=message;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,4500);}

async function api(path,body){
  const response=await fetch(path,{method:body===undefined?'GET':'POST',
    headers:body===undefined?{}:{'Content-Type':'application/json','X-NetScope-Token':token},
    body:body===undefined?undefined:JSON.stringify(body)});
  const value=await response.json();
  if(!response.ok) throw new Error(value.error||'请求失败');
  return value;
}

function openDialog(title,eyebrow,content){
  $('dialog-title').textContent=title;$('dialog-eyebrow').textContent=eyebrow;
  $('dialog-content').innerHTML=content;
  if(!$('detail-dialog').open)$('detail-dialog').showModal();
}

function metric(id,value){
  const display=rate(value);
  if(value==null){$(id).textContent='—';return;}
  const [amount,unit]=display.split(' ');
  $(id).innerHTML=`${esc(amount)}<small>${esc(unit)}</small>`;
}

function chart(id,values,color){
  const canvas=$(id),ctx=canvas.getContext('2d');
  const width=canvas.width,height=canvas.height;
  ctx.clearRect(0,0,width,height);
  const known=values.filter(v=>v!==null);
  if(known.length<2)return;
  const max=Math.max(...known,1);
  ctx.beginPath();let drawing=false;
  values.forEach((value,i)=>{
    if(value===null){drawing=false;return;}
    const x=i/(Math.max(30,values.length)-1)*width,y=height-3-value/max*(height-6);
    if(!drawing){ctx.moveTo(x,y);drawing=true;}else ctx.lineTo(x,y);
  });
  ctx.strokeStyle=color;ctx.lineWidth=1.4;ctx.stroke();
}

function choosePeer(ip){selected=ip;renderFiltered();}

function renderInterfaces(){
  const current=snapshot.selected_interface;
  const options=snapshot.interfaces.filter(item=>item.active||item.name===snapshot.effective_interface||item.name==='lo0');
  const signature=options.map(i=>i.name).join(',')+'|'+snapshot.machine.default_interface;
  if($('interface-select').dataset.signature!==signature){
    $('interface-select').innerHTML=`<option value="auto">自动 · ${esc(snapshot.machine.default_interface||'默认出口')}</option>`
      +options.map(item=>`<option value="${esc(item.name)}">${esc(item.name)}${item.name.startsWith('utun')?' · VPN':item.name==='lo0'?' · 回环':''}</option>`).join('');
    $('interface-select').dataset.signature=signature;
  }
  $('interface-select').value=current;
}

function renderCapture(){
  const capture=snapshot.capture;
  const working=['starting','authorizing','running','stopping'].includes(capture.status);
  const running=capture.status==='running';
  $('packet-count').innerHTML=capture.started_at||capture.packets?capture.packets.toLocaleString('zh-CN'):'—';
  $('packet-caption').textContent=capture.packets?`${bytes(capture.bytes)} · 累计观察量`:running?'等待真实数据包':'尚未开启抓包';
  $('capture-title').textContent=running?'正在捕获真实数据包':capture.status==='error'?'采集未启动':capture.status==='authorizing'?'等待系统授权':'深入到每一个包';
  $('capture-message').textContent=capture.status==='idle'?'开启本机抓包，查看包头、传输方向和原始字节。':capture.message;
  $('capture-dot').style.background=running?'var(--lime)':'var(--amber)';
  $('capture-btn').innerHTML=working?'停止数据包采集 <span>□</span>':capture.status==='error'?'系统授权抓包 <span>↗</span>':'开启数据包采集 <span>↗</span>';
  $('capture-btn').disabled=['starting','stopping'].includes(capture.status);
  $('capture-all').disabled=working;
  $('authorize-btn').hidden=working||capture.status!=='idle';
  $('capture-tag').textContent=running?'CAPTURING':'PCAP';
}

function render(snapshotValue){
  snapshot=snapshotValue;
  metric('rx-rate',snapshot.metrics.rx_bps);metric('tx-rate',snapshot.metrics.tx_bps);
  $('connection-count').textContent=snapshot.sources.connections?.available===false?'—':snapshot.flow_count.toLocaleString('zh-CN');
  $('peer-count').textContent=`${new Set(snapshot.flows.map(f=>f.remote_ip)).size} 个远端 IP · ${snapshot.processes.length} 个进程`;
  $('metric-interface').textContent=`${snapshot.effective_interface||'未识别网卡'} · 当前选定网卡`;
  if(lastSample!==snapshot.updated_at){
    lastSample=snapshot.updated_at;
    for(const axis of ['rx','tx']){history[axis].push(snapshot.metrics[`${axis}_bps`]??null);if(history[axis].length>50)history[axis].shift();}
  }
  chart('rx-chart',history.rx,'#75d6e5');chart('tx-chart',history.tx,'#c4f582');
  renderInterfaces();renderCapture();
  const warnings=Object.entries(snapshot.sources).filter(([,source])=>!source.available);
  $('source-warning').hidden=warnings.length===0;
  $('source-warning').textContent=warnings.length?'部分系统数据不可读取：'+warnings.map(([,source])=>source.error).join('；'):'';
  $('host-label').textContent=snapshot.machine.hostname||'本机设备';
  const iface=snapshot.interfaces.find(i=>i.name===snapshot.effective_interface);
  $('host-ip').textContent=iface?.addresses?.find(ip=>!ip.includes(':'))||iface?.addresses?.[0]||'';
  $('source-label').textContent=`${snapshot.sources.connections?.provider||'macOS'} 连接 · netstat 网卡计数 · ${snapshot.capture.status==='running'?'tcpdump 抓包中':'抓包未运行'}`;
  $('sample-time').textContent=snapshot.updated_at?`采样 ${timeLabel(snapshot.updated_at)}`:'等待首个样本';
  if(!paused){$('live-status').textContent='LIVE · 本机';$('live-dot').classList.remove('offline');}
  renderFiltered();
  if(traceTarget&&$('detail-dialog').open)renderTrace();
}

function renderFiltered(){
  if(!snapshot)return;
  flows=filterFlows(snapshot.flows,filters);
  peers=groupPeers(flows);
  if(selected===null&&peers.length)selected=peers[0].ip;
  $('visible-peers').textContent=peers.length;
  $('graph-empty').hidden=peers.length>0;
  $('peer-list').innerHTML=peers.length?peers.slice(0,120).map(peer=>{
    const first=peer.flows[0];
    return `<button class="peer-row ${peer.ip===selected?'selected':''}" data-peer="${esc(peer.ip)}"><i class="peer-indicator ${protocolClass(peer.protocol)}"></i><span class="peer-text"><span class="peer-ip">${esc(peer.ip)}</span><span class="peer-meta"><span>${esc(first.process||peer.protocol)}${peer.count>1?` +${peer.count-1}`:''}</span><span>${rate((peer.rx_bps??peer.tx_bps)==null?null:(peer.rx_bps||0)+(peer.tx_bps||0))}</span></span></span><span class="peer-arrow">↗</span></button>`;
  }).join(''):'<div class="empty-small">没有符合条件的连接<br>试试调整搜索或显示回环</div>';
  $('tab-flow-count').textContent=flows.length;
  $('tab-packet-count').textContent=snapshot.capture.packets.toLocaleString('zh-CN');
  topology?.update(peers,selected);
  renderPeerDetail();renderTable();
}

function renderPeerDetail(){
  const peer=groupPeers(snapshot.flows).find(p=>p.ip===selected);
  if(!peer){
    if(selected)$('peer-detail').innerHTML='<div class="inspector-placeholder"><span class="target-glyph">◎</span><h3>连接已结束</h3><p>选择另一个活动 IP 查看详情。</p></div>';
    return;
  }
  const processes=[...new Set(peer.flows.map(f=>f.process).filter(Boolean))];
  const ports=[...new Set(peer.flows.map(f=>f.remote_port).filter(p=>p!=null))];
  const interfaces=[...new Set(peer.flows.map(f=>f.interface).filter(Boolean))];
  $('peer-detail').innerHTML=`<div class="peer-detail-header"><div class="eyebrow">REMOTE ENDPOINT</div><div class="selected-ip">${esc(peer.ip)}</div><div class="selected-service">${esc(peer.protocol)} · ${esc(ports.slice(0,4).join(' / ')||'无端口')} · ${peer.count} 条连接</div></div><dl class="detail-grid"><div><dt>接收速率</dt><dd class="cyan">${rate(peer.rx_bps)}</dd></div><div><dt>发送速率</dt><dd class="lime">${rate(peer.tx_bps)}</dd></div><div><dt>Socket 已接收</dt><dd>${bytes(peer.rx_bytes)}</dd></div><div><dt>Socket 已发送</dt><dd>${bytes(peer.tx_bytes)}</dd></div></dl><div class="detail-processes">${esc(processes.join('、')||'进程未归属')}<br>${esc(interfaces.join(' / ')||'未识别网卡')}${ports[0]?` · ${esc(serviceHint(peer.protocol,ports[0]))}（端口推测）`:''}</div><button id="trace-selected" class="button secondary trace-button">探测此 IP 的链路 <span>↗</span></button><div style="height:16px"></div>`;
  $('trace-selected').onclick=()=>startTrace(peer.ip);
}

function emptyTable(title,message,action=''){
  $('table-content').innerHTML=`<div class="empty-state"><span class="empty-icon">◈</span><strong>${esc(title)}</strong><p>${esc(message)}</p>${action}</div>`;
}

function renderTable(){
  const root=$('table-content');
  if(tab==='connections'){
    $('table-caption').textContent='系统 Socket 计数 · 速率按采样差值计算';
    if(!flows.length){emptyTable('暂无匹配的连接','调整筛选条件，或在其他应用中发起网络请求。');}
    else root.innerHTML=`<table><thead><tr><th>远端 IP / 端口</th><th>协议</th><th>进程</th><th>接收 ↓</th><th>发送 ↑</th><th>网卡</th><th>状态</th></tr></thead><tbody>${flows.slice(0,150).map(flow=>`<tr class="table-row ${flow.remote_ip===selected?'selected':''}" data-peer="${esc(flow.remote_ip)}"><td>${esc(endpointLabel(flow.remote_ip,flow.remote_port))}</td><td>${badge(flow.protocol)}</td><td><span class="process-name"><span class="process-avatar">${esc((flow.process||'?')[0].toUpperCase())}</span>${esc(flow.process||'未归属')}<span class="process-pid">${flow.pid||''}</span></span></td><td class="cyan">${rate(flow.rx_bps)}</td><td class="lime">${rate(flow.tx_bps)}</td><td>${esc(flow.interface||'—')}</td><td><span class="state-pill">${esc(flow.state||'OBSERVED')}</span></td></tr>`).join('')}</tbody></table>`;
    $('table-count').textContent=`显示 ${Math.min(flows.length,150)} / ${flows.length} 条连接 · 拓扑最多显示 40 个 IP`;
  } else if(tab==='packets'){
    $('table-caption').textContent='每包保留前 256 字节 · 内存保留最新 600 包';
    const query=filters.query.toLowerCase();
    const packets=snapshot.packets.filter(p=>(filters.protocol==='ALL'||p.protocol===filters.protocol||filters.protocol==='ICMP'&&p.protocol==='ICMPv6')
      &&(!filters.hideLoopback||!loopback(p.src_ip)&&!loopback(p.dst_ip))
      &&(!query||[p.src_ip,p.dst_ip,p.src_port,p.dst_port,p.protocol].join(' ').toLowerCase().includes(query)));
    if(!packets.length){
      emptyTable(snapshot.capture.packets?'暂无匹配的数据包':'尚未开启数据包采集',snapshot.capture.packets?'可调整协议或 IP 筛选。':'授权后显示真实包头与字节，HTTPS 内容仍为加密数据。',
        snapshot.capture.status!=='running'?'<button class="button primary" id="table-capture" style="margin-top:8px;font-size:10px">开启采集 ↗</button>':'');
      $('table-capture')?.addEventListener('click',captureAction);
    }else root.innerHTML=`<table><thead><tr><th>序号 / 时间</th><th>来源</th><th>目标</th><th>协议</th><th>长度</th><th>方向</th><th>包头摘要</th></tr></thead><tbody>${packets.map(p=>`<tr class="table-row" data-packet="${p.id}"><td><span class="muted">#${p.id}</span> ${timeLabel(p.timestamp)}</td><td>${esc(endpointLabel(p.src_ip,p.src_port))}</td><td>${esc(endpointLabel(p.dst_ip,p.dst_port))}</td><td>${badge(p.protocol)}</td><td>${p.length} B</td><td>${({in:'↙ 接收',out:'↗ 发送',local:'↔ 回环',other:'其他'})[p.direction]}</td><td>${esc(p.summary)}</td></tr>`).join('')}</tbody></table>`;
    $('table-count').textContent=`当前窗口 ${packets.length} 包 · 累计 ${snapshot.capture.packets} 包 · 点击查看原始字节`;
  } else {
    $('table-caption').textContent='进程汇总来自 nettop · 含该进程所有网卡';
    const processes=snapshot.processes.filter(p=>!filters.query||`${p.name} ${p.pid}`.toLowerCase().includes(filters.query.toLowerCase()))
      .sort((a,b)=>((b.rx_bps||0)+(b.tx_bps||0))-((a.rx_bps||0)+(a.tx_bps||0)));
    if(!processes.length)emptyTable('暂无进程数据','nettop 不可用时，仍可通过网络连接表查看进程归属。');
    else root.innerHTML=`<table><thead><tr><th>进程</th><th>PID</th><th>接收速率 ↓</th><th>发送速率 ↑</th><th>进程累计接收</th><th>进程累计发送</th></tr></thead><tbody>${processes.map(p=>`<tr><td><span class="process-name"><span class="process-avatar">${esc(p.name[0].toUpperCase())}</span>${esc(p.name)}</span></td><td>${p.pid}</td><td class="cyan">${rate(p.rx_bps)}</td><td class="lime">${rate(p.tx_bps)}</td><td>${bytes(p.rx_bytes)}</td><td>${bytes(p.tx_bytes)}</td></tr>`).join('')}</tbody></table>`;
    $('table-count').textContent=`${processes.length} 个进程 · 累计值自系统记录该进程起`;
  }
}

function setTab(value){tab=value;document.querySelectorAll('.table-tab').forEach(button=>{const active=button.dataset.tab===tab;button.classList.toggle('active',active);button.setAttribute('aria-selected',String(active));});renderTable();}

async function captureAction(){
  if(!snapshot)return;
  try{
    const working=['starting','authorizing','running','stopping'].includes(snapshot.capture.status);
    if(working){await api('/api/capture/stop',{});toast('采集已停止，数据仍保留在本机内存中。');}
    else {
      const iface=$('capture-all').checked?'all':snapshot.effective_interface;
      if(!iface)throw new Error('尚未识别到可采集网卡，请等待系统采样。');
      await api('/api/capture/start',{interface:iface,authorize:snapshot.capture.status==='error'});
      toast(snapshot.capture.status==='error'?'请完成 macOS 系统认证；只有 tcpdump 请求管理员权限。':'正在尝试打开本机采集设备…');
    }
    render(await api('/api/snapshot'));
  }catch(error){toast(error.message);}
}

async function showPacket(id){
  traceTarget=null;
  try{
    const p=await api(`/api/packets/${id}`);
    const fields=[['来源',endpointLabel(p.src_ip,p.src_port)],['目标',endpointLabel(p.dst_ip,p.dst_port)],['协议',p.protocol],
      ['时间',`${timeLabel(p.timestamp)}.${String(Math.round((p.timestamp%1)*1000000)).padStart(6,'0')}`],
      ['线缆 / 原始长度',`${p.length} B`],['实际保留长度',`${p.captured_length} B`],
      ['IP 版本 / TTL',`${p.family} / ${p.ttl??'—'}`],['网卡',p.interface],['TCP Flags',p.tcp_flags?.join(' · ')||'—']];
    let hex='';
    const data=p.hex.match(/.{1,2}/g)||[];
    for(let i=0;i<data.length;i+=16){const row=data.slice(i,i+16);hex+=`<span class="hex-offset">${i.toString(16).padStart(4,'0')}</span>  ${row.join(' ').padEnd(47,' ')}  <span class="hex-ascii">${esc(p.ascii.slice(i,i+16))}</span>\n`;}
    openDialog(`数据包 #${id}`,'PACKET INSPECTOR · REAL BYTES',`<div class="dialog-notice">展示实际采集的包头与原始字节。TLS / HTTPS / QUIC 正文通常已经加密，不等同于明文请求内容。${p.truncated?' 此包已按 256 字节采集上限截断。':''}</div><dl class="packet-metadata">${fields.map(([key,value])=>`<div><dt>${esc(key)}</dt><dd>${esc(value??'—')}</dd></div>`).join('')}</dl><h3 class="subheading">原始字节<span>OFFSET · HEXADECIMAL · ASCII</span></h3><pre class="hex-view">${hex}</pre>`);
  }catch(error){toast(error.message);}
}

async function startTrace(target){
  if(!target){toast('先在拓扑中选择一个远端 IP。');return;}
  traceTarget=target;renderTrace();
  try{await api('/api/trace',{target});latest=await api('/api/snapshot');if(!paused)render(latest);else renderTrace();}
  catch(error){toast(error.message);$('dialog-content').innerHTML=`<div class="dialog-notice amber">${esc(error.message)}</div>`;}
}

function renderTrace(){
  const source=paused?latest:snapshot;
  const result=source?.traces.find(item=>item.target===traceTarget);
  const route=result?.route;
  openDialog('链路探测','ON-DEMAND TRACEROUTE',`<div class="dialog-notice">目标 <span class="mono">${esc(traceTarget)}</span>。这是一次主动探测结果，不代表每个数据包的完整经过路径；VPN、代理及中间设备可使跳点不可见。</div>${route?`<dl class="packet-metadata"><div><dt>系统选择的接口</dt><dd>${esc(route.interface||'—')}</dd></div><div><dt>本地下一跳 / 网关</dt><dd>${esc(route.gateway||'直连 / 未返回')}</dd></div><div><dt>目标</dt><dd>${esc(traceTarget)}</dd></div></dl>`:''}<h3 class="subheading">探测跳点<span>最多 12 跳 · 单跳约 1 秒</span></h3>${result?.hops?.length?result.hops.map(hop=>`<div class="route-hop"><span class="hop-number">${hop.hop}</span><span class="hop-ip">${esc(hop.ip||'* 未响应')}</span><span class="hop-time">${hop.rtt_ms==null?'—':hop.rtt_ms.toFixed(2)+' ms'}</span></div>`).join(''):''}<div class="dialog-body-copy"><p>${!result||result.status==='running'?'正在探测，请稍候…':esc(result.message)}</p></div>`);
}

function about(){
  traceTarget=null;
  openDialog('真实数据，从哪里来？','ABOUT NETSCOPE',`<div class="dialog-body-copy"><p>NetScope 将本机系统工具的输出转换为实时 Three.js 拓扑。没有内置演示流量，没有云端遥测。</p><h3>速率、连接与数据包</h3><p><code>netstat</code> 提供所选单网卡的真实收发字节增量；<code>nettop</code> 提供 Socket 与进程字节计数。统计每 2 秒更新。读不到的数据显示「—」，真实零流量显示「0 B/s」。</p><p><code>lsof</code> 是连接列表的降级来源，此时没有逐连接速率。Socket 累计值从连接建立起计，进程累计值来自系统。两者与本次抓包观察量口径不同。</p><h3>包内容与权限</h3><p><code>tcpdump</code> 在开启采集后读取包；首次无权限时，点击「系统授权抓包」完成 macOS 认证。只有 tcpdump 提权，并用 <code>-Z</code> 降回当前用户；网页服务始终以普通用户运行。</p><p>每包保留前 256 字节，最新 600 包留在内存。停止采集不会清空这些记录，退出服务后释放。HTTPS / TLS / QUIC 正文通常加密，本工具不解密。</p><h3>拓扑与真实链路</h3><p>连线表示本机与远端 IP 的逻辑连接。流光由实测 Socket 活动或新捕获的包驱动，不代表每个包的精确时间回放。最多可视化当前筛选中的 40 个 IP。</p><p>链路探测使用 <code>route</code> 与 <code>traceroute</code>，只在你点击后发起。未知跳点保留未知。端口对应服务仅是提示，不能证明应用层协议。代理 / VPN 可能使终点仅表现为代理服务器 IP。</p><h3>网卡选择</h3><p>上方网卡仅影响四项指标中的收发速率和新抓包的接口。连接表与拓扑展示全机观测到的 Socket；进程页包含所有接口。默认统计单网卡，避免把 VPN 和物理网卡的同一流量重复相加。「所有接口」抓包可能多次观察到同一包，观察量不是独立包去重数。</p><h3>本地启动</h3><pre class="command">npm install\nnpm start\n# 浏览器打开 http://127.0.0.1:8765</pre><p>全部前端依赖随本地安装提供，无需外部 CDN。服务只监听 <code>127.0.0.1</code>，不能从局域网或其他设备访问。</p><p>参考：<a href="https://threejs.org/docs/pages/OrbitControls" target="_blank" rel="noopener noreferrer">Three.js OrbitControls</a> · <a href="https://www.tcpdump.org/manpages/tcpdump.1.html" target="_blank" rel="noopener noreferrer">tcpdump 文档</a></p></div>`);
}

function bind(){
  $('search').addEventListener('input',event=>{filters.query=event.target.value;renderFiltered();});
  $('show-loopback').addEventListener('change',event=>{filters.hideLoopback=!event.target.checked;renderFiltered();});
  $('protocol-filters').addEventListener('click',event=>{const button=event.target.closest('[data-protocol]');if(!button)return;filters.protocol=button.dataset.protocol;document.querySelectorAll('.filter-chip').forEach(b=>b.classList.toggle('active',b===button));renderFiltered();});
  $('peer-list').addEventListener('click',event=>{const row=event.target.closest('[data-peer]');if(row)choosePeer(row.dataset.peer);});
  $('table-content').addEventListener('click',event=>{const packet=event.target.closest('[data-packet]'),peer=event.target.closest('[data-peer]');if(packet)showPacket(packet.dataset.packet);else if(peer)choosePeer(peer.dataset.peer);});
  document.querySelectorAll('.table-tab').forEach(button=>button.addEventListener('click',()=>setTab(button.dataset.tab)));
  $('pause-btn').onclick=()=>{paused=!paused;$('pause-text').textContent=paused?'恢复显示':'暂停显示';$('pause-icon').textContent=paused?'▷':'Ⅱ';$('live-status').textContent=paused?'PAUSED':'LIVE · 本机';if(topology)topology.paused=paused;if(!paused&&latest)render(latest);toast(paused?'显示已暂停，后台采集继续运行。':'已恢复实时显示。');};
  $('interface-select').onchange=async event=>{try{await api('/api/interface',{interface:event.target.value});render(await api('/api/snapshot'));toast('已切换统计网卡；连接拓扑仍显示全机连接。');}catch(error){toast(error.message);}};
  $('capture-btn').onclick=captureAction;
  $('authorize-btn').onclick=async()=>{try{await api('/api/capture/start',{interface:$('capture-all').checked?'all':snapshot.effective_interface,authorize:true});render(await api('/api/snapshot'));}catch(error){toast(error.message);}};
  $('reset-view').onclick=()=>topology?.reset();
  $('fullscreen-btn').onclick=()=>{const panel=document.querySelector('.observatory');panel.classList.toggle('expanded');$('fullscreen-btn').title=panel.classList.contains('expanded')?'收起拓扑':'展开拓扑';};
  $('dialog-close').onclick=()=>$('detail-dialog').close();
  $('detail-dialog').addEventListener('close',()=>{traceTarget=null;});
  $('detail-dialog').addEventListener('click',event=>{if(event.target===$('detail-dialog')){const rect=$('detail-dialog').getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)$('detail-dialog').close();}});
  document.addEventListener('keydown',event=>{if(event.key==='Escape')document.querySelector('.observatory').classList.remove('expanded');});
  $('about-btn').onclick=about;
  $('nav-topology').onclick=()=>{document.querySelector('.observatory').scrollIntoView({behavior:'smooth'});setNav('nav-topology');};
  $('nav-packets').onclick=()=>{setTab('packets');$('traffic-panel').scrollIntoView({behavior:'smooth',block:'nearest'});setNav('nav-packets');};
  $('nav-route').onclick=()=>{startTrace(selected);setNav('nav-route');};
}

function setNav(id){for(const name of ['nav-topology','nav-packets','nav-route'])$(name).classList.toggle('active',name===id);}

async function init(){
  bind();
  try{
    const config=await api('/api/config');token=config.token;
    render(await api('/api/snapshot'));
    const events=new EventSource('/api/events');
    events.onmessage=event=>{lastSeen=Date.now();latest=JSON.parse(event.data);if(!paused)render(latest);else if(traceTarget&&$('detail-dialog').open)renderTrace();};
    events.onerror=()=>{$('live-status').textContent='重连中';$('live-dot').classList.add('offline');};
  }catch(error){$('source-warning').hidden=false;$('source-warning').textContent=`本机采集服务不可用：${error.message}。请执行 npm start。`;}
  try{
    const {Topology}=await import('./topology.js');
    topology=new Topology($('topology'),$('graph-labels'),choosePeer);
    if(snapshot)topology.update(peers,selected);
  }catch(error){
    $('topology').innerHTML='<div class="webgl-fallback">当前浏览器无法启动 WebGL 2。<br>真实连接、流量与数据包仍可从列表查看。<br>请尝试启用浏览器硬件加速。</div>';
    console.warn('Three.js unavailable:',error);
  }
  $('topology').addEventListener('graph-error',event=>toast(event.detail));
  setInterval(()=>{const now=new Date();$('footer-clock').textContent=now.toLocaleTimeString('zh-CN',{hour12:false});if(lastSeen&&Date.now()-lastSeen>6000&&!paused){$('live-status').textContent='数据连接中断';$('live-dot').classList.add('offline');}},1000);
}

init();

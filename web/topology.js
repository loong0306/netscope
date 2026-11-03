import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

const colors = {TCP:0xc4f582, UDP:0x75d6e5, ICMP:0xbe9ddd, ICMPv6:0xbe9ddd};
const colorFor = protocol => colors[protocol] || 0x8399ab;

export class Topology {
  constructor(container, labels, onSelect) {
    this.container = container;
    this.labels = labels;
    this.onSelect = onSelect;
    this.nodes = new Map();
    this.selected = null;
    this.paused = false;
    this.reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x0d131a, .022);
    this.camera = new THREE.PerspectiveCamera(43, 1, .1, 150);
    this.renderer = new THREE.WebGLRenderer({antialias:true, alpha:true, powerPreference:'low-power'});
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 1.7));
    this.renderer.setClearColor(0x0d131a, 0);
    this.renderer.outputColorSpace = THREE.SRGBColorSpace;
    container.append(this.renderer.domElement);
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = .07;
    this.controls.minDistance = 9;
    this.controls.maxDistance = 50;
    this.controls.maxPolarAngle = Math.PI * .47;
    this.controls.enablePan = true;
    this.reset();
    this.scene.add(new THREE.AmbientLight(0xc5efd5, 1.5));
    const light = new THREE.PointLight(0xd7ffaa, 35, 28);
    light.position.set(0, 6, 0);
    this.scene.add(light);
    const grid = new THREE.GridHelper(60, 40, 0x314438, 0x1e2e2c);
    grid.material.transparent = true;
    grid.material.opacity = .27;
    grid.position.y = -.3;
    this.scene.add(grid);
    const circlePoints = [];
    for (let i=0; i<=128; i++) {
      const angle = i / 128 * Math.PI * 2;
      circlePoints.push(new THREE.Vector3(Math.cos(angle)*8, -.25, Math.sin(angle)*8));
    }
    this.scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(circlePoints),
      new THREE.LineDashedMaterial({color:0x3c5442, transparent:true, opacity:.4, dashSize:.13, gapSize:.23})).computeLineDistances());
    this.host = new THREE.Group();
    this.host.position.y = .7;
    const core = new THREE.Mesh(new THREE.IcosahedronGeometry(.55, 1),
      new THREE.MeshStandardMaterial({color:0xc4f582, emissive:0x4b6c27, emissiveIntensity:.6,
        metalness:.6, roughness:.4, flatShading:true}));
    this.host.add(core);
    this.hostWire = new THREE.Mesh(new THREE.IcosahedronGeometry(.8, 1),
      new THREE.MeshBasicMaterial({color:0xc4f582, wireframe:true, transparent:true, opacity:.25}));
    this.host.add(this.hostWire);
    for (const radius of [1.15,1.4,1.65]) {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(radius, .008, 4, 80),
        new THREE.MeshBasicMaterial({color:0x98c476, transparent:true, opacity:radius===1.15 ? .6 : .2}));
      ring.rotation.x = Math.PI/2;
      ring.position.y = -.5;
      this.host.add(ring);
    }
    this.scene.add(this.host);
    this.hostLabel = document.createElement('span');
    this.hostLabel.className = 'node-label host';
    this.hostLabel.textContent = 'THIS DEVICE';
    labels.append(this.hostLabel);
    this.raycaster = new THREE.Raycaster();
    this.pointer = new THREE.Vector2();
    let down = null;
    this.renderer.domElement.addEventListener('pointerdown', event => {down=[event.clientX,event.clientY];});
    this.renderer.domElement.addEventListener('pointerup', event => {
      if (!down || Math.hypot(event.clientX-down[0],event.clientY-down[1])>5) return;
      const rect=this.renderer.domElement.getBoundingClientRect();
      this.pointer.set((event.clientX-rect.left)/rect.width*2-1, -(event.clientY-rect.top)/rect.height*2+1);
      this.raycaster.setFromCamera(this.pointer,this.camera);
      const hit=this.raycaster.intersectObjects([...this.nodes.values()].map(n=>n.mesh))[0];
      if(hit) this.onSelect(hit.object.userData.ip);
    });
    this.resizeObserver = new ResizeObserver(()=>this.resize());
    this.resizeObserver.observe(container.parentElement);
    this.resize();
    this.lastFrame=0;
    this.animate = this.animate.bind(this);
    this.animation = requestAnimationFrame(this.animate);
    this.renderer.domElement.addEventListener('webglcontextlost', event => {
      event.preventDefault();
      cancelAnimationFrame(this.animation);
      container.dispatchEvent(new CustomEvent('graph-error', {detail:'图形上下文已丢失，请刷新页面重新加载。'}));
    });
  }

  reset() {
    this.camera.position.set(12, 16, 22);
    if (this.controls) {this.controls.target.set(0,0,0);this.controls.update();}
  }

  resize() {
    const rect=this.container.parentElement.getBoundingClientRect();
    if(!rect.width||!rect.height) return;
    this.renderer.setSize(rect.width,rect.height);
    this.camera.aspect=rect.width/rect.height;
    this.camera.updateProjectionMatrix();
  }

  addPeer(peer, slot) {
    const group=new THREE.Group();
    const angle=slot%16/16*Math.PI*2 + Math.floor(slot/16)*.2;
    const radius=6.4+Math.floor(slot/16)*2.8;
    const position=new THREE.Vector3(Math.cos(angle)*radius, .5+(slot%4)*.35, Math.sin(angle)*radius);
    const material=new THREE.MeshBasicMaterial({color:colorFor(peer.protocol)});
    const mesh=new THREE.Mesh(new THREE.IcosahedronGeometry(.14,1),material);
    mesh.position.copy(position);
    mesh.userData.ip=peer.ip;
    const halo=new THREE.Mesh(new THREE.SphereGeometry(.29,12,8),
      new THREE.MeshBasicMaterial({color:colorFor(peer.protocol),transparent:true,opacity:.08,depthWrite:false}));
    halo.position.copy(position);
    group.add(mesh,halo);
    const curve=new THREE.QuadraticBezierCurve3(new THREE.Vector3(0,.7,0),
      new THREE.Vector3(position.x*.5,2.1+radius*.1,position.z*.5),position);
    const line=new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(45)),
      new THREE.LineBasicMaterial({color:colorFor(peer.protocol),transparent:true,opacity:.17}));
    group.add(line);
    const base=new THREE.Mesh(new THREE.RingGeometry(.2,.23,24),
      new THREE.MeshBasicMaterial({color:colorFor(peer.protocol),side:THREE.DoubleSide,transparent:true,opacity:.25}));
    base.rotation.x=-Math.PI/2;
    base.position.set(position.x,-.2,position.z);
    group.add(base);
    const particles=[];
    for(let i=0;i<4;i++) {
      const particle=new THREE.Mesh(new THREE.SphereGeometry(i%2 ? .035:.045,6,4),
        new THREE.MeshBasicMaterial({color:i%2 ? 0x75d6e5:0xc4f582,transparent:true,opacity:.9}));
      particle.visible=false;
      group.add(particle);particles.push(particle);
    }
    const label=document.createElement('button');
    label.className='node-label';label.textContent=peer.ip;
    label.title=`${peer.ip} · 点击查看连接`;
    label.addEventListener('click',()=>this.onSelect(peer.ip));
    this.labels.append(label);
    this.scene.add(group);
    const node={group,mesh,halo,line,curve,particles,label,position,slot,peer,packetChanged:false};
    this.nodes.set(peer.ip,node);
    return node;
  }

  update(peers, selected) {
    this.selected=selected;
    const shown=peers.slice(0,40);
    const keep=new Set(shown.map(p=>p.ip));
    for(const [ip,node] of this.nodes) {
      if(!keep.has(ip)) {
        this.scene.remove(node.group);node.label.remove();
        node.group.traverse(object=>{object.geometry?.dispose();object.material?.dispose();});
        this.nodes.delete(ip);
      }
    }
    const used=new Set([...this.nodes.values()].map(n=>n.slot));
    for(const peer of shown) {
      let node=this.nodes.get(peer.ip);
      if(!node) {let slot=0;while(used.has(slot))slot++;used.add(slot);node=this.addPeer(peer,slot);}
      node.packetChanged=peer.packets>(node.peer.packets||0);
      node.peer=peer;
      const active=peer.ip===selected;
      node.mesh.scale.setScalar(active?1.7:1);
      node.halo.material.opacity=active?.2:.08;
      node.line.material.opacity=active?.65:.17;
      node.label.classList.toggle('selected',active);
    }
  }

  projectLabel(element,position) {
    const point=position.clone().project(this.camera);
    const width=this.renderer.domElement.clientWidth,height=this.renderer.domElement.clientHeight;
    element.hidden=point.z>1||point.z< -1||Math.abs(point.x)>1.15||Math.abs(point.y)>1.15;
    element.style.left=`${(point.x*.5+.5)*width}px`;
    element.style.top=`${(-point.y*.5+.5)*height}px`;
  }

  animate(now) {
    this.animation=requestAnimationFrame(this.animate);
    if(document.hidden || now-this.lastFrame<32) return;
    this.lastFrame=now;
    this.controls.update();
    if(!this.paused&&!this.reducedMotion) this.hostWire.rotation.y=now*.00008;
    const t=now*.00018;
    for(const node of this.nodes.values()) {
      this.projectLabel(node.label,node.position);
      const received=(node.peer.rx_bps||0)>0;
      const sent=(node.peer.tx_bps||0)>0;
      node.particles.forEach((particle,i)=>{
        const enabled=!this.reducedMotion && (i%2?received:sent)||(!this.reducedMotion&&node.packetChanged&&i===0);
        particle.visible=enabled;
        if(enabled&&!this.paused) {
          const fraction=(t*(1+Math.min(2,Math.log10(1+(node.peer.rx_bps||0)+(node.peer.tx_bps||0))*.2))+i*.23)%1;
          particle.position.copy(node.curve.getPoint(i%2?1-fraction:fraction));
        }
      });
    }
    this.projectLabel(this.hostLabel,new THREE.Vector3(0,1.25,0));
    this.renderer.render(this.scene,this.camera);
  }
}

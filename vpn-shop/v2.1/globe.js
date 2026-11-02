/* =========================================================================
   SilentConnect 3D Metallic Globe (Resend Hardware Approach):
   - Full Studio PMREM Reflections, Extruded Squircle Bezel & Continent Relief
   - Adaptive Mobile Mesh (128x64 on mobile vs 280x140 on desktop) +
     Strict IntersectionObserver Pause so scrolling checkout has 0% GPU load.
   ========================================================================= */
import * as THREE from 'three';
import { mergeVertices } from 'three/addons/utils/BufferGeometryUtils.js';

const stage = document.getElementById('stage');

function initGlobe(){
const isMobile = window.matchMedia('(max-width: 860px)').matches;

const LAND = [
  [[-168,66],[-162,70],[-156,71],[-140,70],[-128,70],[-115,68],[-95,72],[-82,73],[-80,63],[-94,59],[-90,55],[-82,52],[-78,58],[-70,60],[-62,58],[-56,52],[-60,47],[-66,44],[-70,42],[-76,38],[-76,35],[-81,31],[-80,26],[-82,26],[-84,30],[-90,30],[-97,28],[-97,22],[-92,18],[-88,21],[-87,16],[-83,10],[-79,9],[-80,7],[-85,10],[-92,14],[-100,17],[-106,23],[-112,30],[-110,24],[-115,30],[-117,33],[-121,35],[-124,40],[-124,46],[-125,49],[-131,54],[-138,59],[-146,61],[-152,59],[-158,57],[-164,55],[-158,58],[-162,60],[-166,62],[-164,64]],
  [[-120,72],[-100,73],[-80,74],[-65,82],[-90,82],[-115,78],[-122,75]],
  [[-73,78],[-60,82],[-35,83],[-20,82],[-18,76],[-22,70],[-32,68],[-42,60],[-50,62],[-54,67],[-58,75]],
  [[-24,64],[-14,64],[-14,66.5],[-22,66.5]],
  [[-80,9],[-75,11],[-72,12],[-63,10],[-60,8],[-52,5],[-50,0],[-44,-2],[-35,-5],[-35,-9],[-39,-14],[-39,-18],[-41,-22],[-48,-26],[-49,-29],[-53,-34],[-58,-35],[-57,-38],[-62,-39],[-65,-42],[-66,-47],[-69,-51],[-68,-55],[-72,-54],[-75,-50],[-74,-44],[-73,-37],[-71,-30],[-70,-18],[-76,-14],[-81,-6],[-80,-2],[-78,2],[-78,7]],
  [[-10,36],[-9,43],[-2,43],[-1,46],[-5,48],[2,51],[5,53],[8,54],[8,57],[10,59],[5,59],[5,62],[12,66],[18,70],[26,71],[32,70],[40,68],[44,66],[50,68],[60,69],[68,72],[75,72],[80,73],[90,75],[100,77],[110,76],[115,73],[130,71],[140,72],[150,71],[160,70],[170,70],[180,68],[180,65],[175,64],[178,62],[170,60],[163,58],[160,54],[156,51],[156,57],[160,61],[152,59],[142,59],[136,54],[140,48],[132,43],[128,39],[126,35],[127,38],[125,40],[121,40],[118,38],[121,37],[119,35],[121,32],[122,30],[119,25],[114,22],[108,21],[106,18],[109,12],[105,9],[103,10],[100,13],[100,8],[103,2],[101,3],[98,8],[98,16],[94,18],[92,22],[88,22],[86,20],[80,15],[80,10],[77,8],[73,16],[73,21],[68,23],[62,25],[57,26],[56,24],[59,22],[52,16],[45,13],[43,15],[39,22],[35,28],[33,30],[35,33],[36,36],[30,36],[27,37],[26,40],[29,41],[23,40],[23,37],[21,38],[20,40],[19,42],[15,45],[13,45],[16,42],[18,40],[16,38],[12,42],[9,44],[3,43],[-1,37],[-6,36]],
  [[-5,50],[1,51],[2,53],[-2,56],[-2,58.5],[-5,58.5],[-6,56],[-4,54],[-5,52]],
  [[-17,21],[-16,28],[-10,30],[-6,35],[0,36],[10,37],[11,33],[20,31],[25,32],[32,31],[34,28],[38,22],[43,12],[51,12],[48,5],[42,-1],[40,-10],[40,-16],[35,-24],[33,-28],[28,-33],[20,-35],[18,-32],[15,-27],[12,-18],[13,-10],[9,-1],[9,4],[5,6],[-2,5],[-8,4],[-13,8],[-17,14]],
  [[114,-22],[114,-34],[118,-35],[124,-33],[131,-31],[135,-35],[138,-35],[141,-38],[147,-38.5],[150,-37],[153,-31],[153,-25],[146,-19],[142,-11],[141,-17],[136,-12],[130,-11],[126,-14],[122,-18]]
];

function buildHeightField(){
  const W = isMobile ? 512 : 1024, H = isMobile ? 256 : 512;
  const c = document.createElement('canvas'); c.width = W; c.height = H;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#000'; ctx.fillRect(0,0,W,H);
  ctx.fillStyle = '#fff';
  for (const poly of LAND){
    ctx.beginPath();
    poly.forEach(([lon,lat],i)=>{
      const x = (lon+180)/360*W, y = (90-lat)/180*H;
      i ? ctx.lineTo(x,y) : ctx.moveTo(x,y);
    });
    ctx.closePath(); ctx.fill();
  }
  const src = ctx.getImageData(0,0,W,H).data;
  const w = isMobile ? 256 : 512, h = isMobile ? 128 : 256;
  let f = new Float32Array(w*h);
  for (let y=0;y<h;y++) for (let x=0;x<w;x++){
    let s=0;
    for (let dy=0;dy<2;dy++) for (let dx=0;dx<2;dx++) s += src[((y*2+dy)*W + (x*2+dx))*4];
    f[y*w+x] = s/(4*255);
  }
  function blur(a, r){
    const t = new Float32Array(w*h), o = new Float32Array(w*h), n = 2*r+1;
    for (let y=0;y<h;y++){
      let s=0; for (let k=-r;k<=r;k++) s += a[y*w + ((k+w)%w)];
      for (let x=0;x<w;x++){
        t[y*w+x] = s/n;
        s += a[y*w + ((x+r+1)%w)] - a[y*w + ((x-r+w)%w)];
      }
    }
    for (let x=0;x<w;x++){
      let s=0; for (let k=-r;k<=r;k++) s += t[Math.min(h-1,Math.max(0,k))*w + x];
      for (let y=0;y<h;y++){
        o[y*w+x] = s/n;
        s += t[Math.min(h-1,y+r+1)*w+x] - t[Math.max(0,y-r)*w+x];
      }
    }
    return o;
  }
  f = blur(f,2);
  if (!isMobile) f = blur(f,2);
  const ss = (a,b,x)=>{ const t=Math.min(1,Math.max(0,(x-a)/(b-a))); return t*t*(3-2*t); };
  for (let i=0;i<f.length;i++) f[i] = ss(0.32,0.68,f[i]);
  f = blur(f,1);
  return { data:f, w, h };
}

const renderer = new THREE.WebGLRenderer({ antialias:true, alpha:true, powerPreference: isMobile ? 'default' : 'high-performance' });
renderer.setPixelRatio(Math.min(window.devicePixelRatio, isMobile ? 1.35 : 2));
renderer.outputColorSpace = THREE.SRGBColorSpace;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.08;
renderer.setClearColor(0x000000, 0);
stage.appendChild(renderer.domElement);

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 100);
camera.position.set(0, 0.05, 6.25);
camera.lookAt(0, -0.05, 0);

function buildEnvironment(){
  const env = new THREE.Scene();
  const dome = new THREE.Mesh(
    new THREE.SphereGeometry(20, 32, 16),
    new THREE.ShaderMaterial({
      side: THREE.BackSide, depthWrite:false,
      vertexShader:`varying vec3 vP; void main(){ vP = normalize(position); gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.); }`,
      fragmentShader:`varying vec3 vP; void main(){
        float t = vP.y*0.5+0.5;
        vec3 top = vec3(0.048,0.052,0.06);
        vec3 bot = vec3(0.004,0.032,0.022);
        vec3 c = mix(bot, top, smoothstep(0.0,1.0,t));
        c += vec3(0.02,0.52,0.32) * pow(max(-vP.y,0.0), 4.0) * 1.05;
        gl_FragColor = vec4(c,1.); }`
    })
  );
  env.add(dome);
  const softbox = (w,h,intensity,color,pos,look)=>{
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w,h), new THREE.MeshBasicMaterial({ color:new THREE.Color(color).multiplyScalar(intensity), side:THREE.DoubleSide }));
    m.position.copy(pos); m.lookAt(look||new THREE.Vector3()); env.add(m); return m;
  };
  softbox(7, 4.5, 3.2, 0xffffff, new THREE.Vector3(-5, 6, 6));
  softbox(1.4, 9, 2.2, 0xe8eef5, new THREE.Vector3(8, 1, 2));
  softbox(1.0, 8, 1.4, 0xdfe6ee, new THREE.Vector3(-8, 0, -2));
  softbox(6, 1.2, 1.6, 0xffffff, new THREE.Vector3(2, 8, -5));
  softbox(9, 4, 1.8, 0x2bdc9a, new THREE.Vector3(0, -7, 1.5));
  const pmrem = new THREE.PMREMGenerator(renderer);
  const tex = pmrem.fromScene(env, 0.03).texture;
  pmrem.dispose();
  return tex;
}
scene.environment = buildEnvironment();

function radialTexture(stops){
  const c = document.createElement('canvas'); c.width = c.height = 128;
  const g = c.getContext('2d');
  const grad = g.createRadialGradient(64,64,0,64,64,64);
  stops.forEach(([o,col])=>grad.addColorStop(o,col));
  g.fillStyle = grad; g.fillRect(0,0,128,128);
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; return t;
}

const cardGroup = new THREE.Group();
scene.add(cardGroup);
function squircleShape(size, n=4.2, seg=80){
  const s = new THREE.Shape(), a = size/2;
  for (let i=0;i<=seg;i++){
    const t = i/seg*Math.PI*2, c = Math.cos(t), si = Math.sin(t);
    const x = Math.sign(c)*Math.pow(Math.abs(c),2/n)*a;
    const y = Math.sign(si)*Math.pow(Math.abs(si),2/n)*a;
    i ? s.lineTo(x,y) : s.moveTo(x,y);
  }
  return s;
}
const CARD_Z = -1.35;
const cardGeo = new THREE.ExtrudeGeometry(squircleShape(3.35), {
  depth:0.12, bevelEnabled:true, bevelThickness:0.06, bevelSize:0.06, bevelSegments: isMobile ? 3 : 5, curveSegments: isMobile ? 64 : 100
});
cardGeo.center();
const cardMat = new THREE.MeshPhysicalMaterial({
  color:0x121519, metalness:0.76, roughness:0.36, clearcoat:1, clearcoatRoughness:0.2, envMapIntensity:0.95
});
const card = new THREE.Mesh(cardGeo, cardMat);
card.position.z = CARD_Z;
cardGroup.add(card);

const bezel = new THREE.Mesh(
  new THREE.ShapeGeometry(squircleShape(3.18), 1),
  new THREE.MeshPhysicalMaterial({ color:0x0a0b0d, metalness:0.6, roughness:0.5, clearcoat:0.6, clearcoatRoughness:0.35 })
);
bezel.position.z = CARD_Z + 0.121;
cardGroup.add(bezel);

const cardGlow = new THREE.Mesh(
  new THREE.PlaneGeometry(3.6, 3.0),
  new THREE.MeshBasicMaterial({
    map: radialTexture([[0,'rgba(40,235,155,0.62)'],[0.3,'rgba(16,185,120,0.28)'],[0.65,'rgba(10,110,75,0.06)'],[1,'rgba(0,0,0,0)']]),
    transparent:true, blending:THREE.AdditiveBlending, depthWrite:false
  })
);
cardGlow.position.set(0, -0.95, CARD_Z + 0.125);
cardGroup.add(cardGlow);

const hf = buildHeightField();
function sampleH(lon, lat){
  const u = (lon/(Math.PI*2)+0.5)*hf.w - 0.5;
  const v = (0.5 - lat/Math.PI)*hf.h - 0.5;
  const x0 = Math.floor(u), y0 = Math.floor(v), fx = u-x0, fy = v-y0;
  const g = (x,y)=> hf.data[Math.min(hf.h-1,Math.max(0,y))*hf.w + ((x%hf.w)+hf.w)%hf.w];
  return (g(x0,y0)*(1-fx)+g(x0+1,y0)*fx)*(1-fy) + (g(x0,y0+1)*(1-fx)+g(x0+1,y0+1)*fx)*fy;
}

const R = 1, EXTRUDE = 0.045;
const segW = isMobile ? 128 : 280, segH = isMobile ? 64 : 140;
let geo = new THREE.SphereGeometry(R, segW, segH);
geo.deleteAttribute('uv'); geo.deleteAttribute('normal');
geo = mergeVertices(geo, 1e-5);
{
  const pos = geo.attributes.position, hArr = new Float32Array(pos.count), v = new THREE.Vector3();
  for (let i=0;i<pos.count;i++){
    v.fromBufferAttribute(pos,i).normalize();
    const lat = Math.asin(THREE.MathUtils.clamp(v.y,-1,1));
    const lon = Math.atan2(v.x, v.z);
    const h = sampleH(lon, lat);
    hArr[i] = h;
    v.multiplyScalar(R + h*EXTRUDE);
    pos.setXYZ(i, v.x, v.y, v.z);
  }
  geo.setAttribute('aH', new THREE.BufferAttribute(hArr,1));
  geo.computeVertexNormals();
}

const uniforms = { uTime:{ value:0 } };
const globeMat = new THREE.MeshPhysicalMaterial({
  color:0x2b2f35, metalness:1.0, roughness:0.28,
  clearcoat:1.0, clearcoatRoughness:0.07,
  envMapIntensity:1.18
});
globeMat.onBeforeCompile = (s)=>{
  s.uniforms.uTime = uniforms.uTime;
  s.vertexShader = s.vertexShader
    .replace('#include <common>', `#include <common>
      attribute float aH; varying float vH; varying vec3 vObjPos; varying vec3 vWN;`)
    .replace('#include <begin_vertex>', `#include <begin_vertex>
      vH = aH; vObjPos = position; vWN = normalize(mat3(modelMatrix) * objectNormal);`);
  s.fragmentShader = s.fragmentShader
    .replace('#include <common>', `#include <common>
      uniform float uTime; varying float vH; varying vec3 vObjPos; varying vec3 vWN;`)
    .replace('#include <roughnessmap_fragment>', `#include <roughnessmap_fragment>
      roughnessFactor = clamp(roughnessFactor + vH*0.12, 0.04, 1.0);`)
    .replace('#include <emissivemap_fragment>', `#include <emissivemap_fragment>
      {
        vec3 dir = normalize(vObjPos);
        float lat = asin(clamp(dir.y, -1.0, 1.0));
        float f = lat / PI * 34.0;
        float fw = max(fwidth(f), 1e-4);
        float d = abs(fract(f + 0.5) - 0.5);
        float line = 1.0 - smoothstep(0.0, fw * 1.3, d);
        line *= smoothstep(0.985, 0.88, abs(dir.y));
        vec3 wn = normalize(vWN);
        float bottom = smoothstep(0.15, -0.95, wn.y);
        float scan = exp(-pow((dir.y - sin(uTime*0.35)*0.95) * 7.0, 2.0));
        vec3 base = vec3(0.62, 0.70, 0.68) * (0.035 + vH*0.06);
        vec3 green = vec3(0.08, 0.88, 0.54) * (0.44 + vH*0.42);
        vec3 lc = mix(base, green, bottom*bottom) * (1.0 + scan*2.0);
        totalEmissiveRadiance += lc * line;
        totalEmissiveRadiance += vec3(0.02, 0.45, 0.26) * pow(bottom, 3.0) * 0.16;
      }`);
};

const tiltGroup = new THREE.Group();
const globe = new THREE.Mesh(geo, globeMat);
tiltGroup.add(globe);
tiltGroup.position.y = 0.08;
scene.add(tiltGroup);

const halo = new THREE.Mesh(
  new THREE.PlaneGeometry(3.4, 2.0),
  new THREE.MeshBasicMaterial({
    map: radialTexture([[0,'rgba(60,235,160,0.8)'],[0.25,'rgba(16,185,120,0.4)'],[0.6,'rgba(8,110,65,0.09)'],[1,'rgba(0,0,0,0)']]),
    transparent:true, blending:THREE.AdditiveBlending, depthWrite:false
  })
);
halo.position.set(0, -0.85, -0.35);
scene.add(halo);

scene.add(new THREE.AmbientLight(0xffffff, 0.05));
const key = new THREE.DirectionalLight(0xffffff, 1.15);
key.position.set(-3, 4, 5); scene.add(key);
const sweep = new THREE.DirectionalLight(0xe9f1ff, 1.6);
scene.add(sweep);
const greenUnder = new THREE.PointLight(0x22e39a, 14, 7, 2);
greenUnder.position.set(0, -1.65, 0.6); scene.add(greenUnder);

let rotY = -0.32, velY = 0, tilt = 0.36, tiltTarget = 0.36;
let dragging = false, lastX = 0, lastY = 0, lastT = 0;
const IDLE = 0.13;
const hover = { x:0, y:0, tx:0, ty:0 };

stage.addEventListener('pointerdown', e=>{
  if (e.pointerType === 'mouse' && e.button !== 0) return;
  dragging = true; stage.classList.add('dragging');
  lastX = e.clientX; lastY = e.clientY; lastT = performance.now();
});
stage.addEventListener('pointermove', e=>{
  const r = stage.getBoundingClientRect();
  hover.tx = ((e.clientX - r.left)/r.width - 0.5);
  hover.ty = ((e.clientY - r.top)/r.height - 0.5);
  if (!dragging) return;
  const now = performance.now(), dt = Math.max(1, now-lastT)/1000;
  const dx = e.clientX - lastX, dy = e.clientY - lastY;
  if (e.pointerType === 'touch' && Math.abs(dy) > Math.abs(dx) * 1.5) return;
  const k = 4.2 / Math.max(120, r.width);
  rotY += dx * k;
  velY = THREE.MathUtils.lerp(velY, (dx*k)/dt, 0.5);
  tiltTarget = THREE.MathUtils.clamp(tiltTarget + dy*k*0.65, -0.65, 0.85);
  lastX = e.clientX; lastY = e.clientY; lastT = now;
});
const endDrag = ()=>{ dragging = false; stage.classList.remove('dragging'); };
addEventListener('pointerup', endDrag);
addEventListener('pointercancel', endDrag);
stage.addEventListener('pointerleave', ()=>{ hover.tx = 0; hover.ty = 0; });

function resize(){
  const w = stage.clientWidth, h = stage.clientHeight;
  if (!w || !h) return;
  renderer.setSize(w, h, false);
  camera.aspect = w/h;
  camera.updateProjectionMatrix();
}
new ResizeObserver(resize).observe(stage);
resize();

let visible = true;
new IntersectionObserver(es => { visible = es[0].isIntersecting; }, { threshold:0.01 }).observe(stage);

const clock = new THREE.Clock();
function tick(){
  requestAnimationFrame(tick);
  const dt = Math.min(clock.getDelta(), 0.05);
  if (!visible || document.hidden) return;
  const t = clock.elapsedTime;
  uniforms.uTime.value = t;

  if (!dragging){
    rotY += (IDLE + velY) * dt;
    velY *= Math.pow(0.04, dt);
    tiltTarget = THREE.MathUtils.lerp(tiltTarget, 0.36, 1 - Math.pow(0.35, dt));
  }
  tilt = THREE.MathUtils.lerp(tilt, tiltTarget, 1 - Math.pow(0.0005, dt));
  globe.rotation.y = rotY;
  tiltGroup.rotation.x = tilt;
  tiltGroup.position.y = 0.08 + Math.sin(t*0.9)*0.032;

  const a = t*0.45;
  sweep.position.set(Math.cos(a)*5, 2.5 + Math.sin(a*0.7)*1.5, Math.sin(a)*3 + 3.5);
  sweep.intensity = 1.0 + Math.max(0, Math.sin(a))*1.4;

  const pulse = 0.88 + Math.sin(t*1.6)*0.12;
  greenUnder.intensity = 14 * pulse;
  halo.material.opacity = 0.75 * pulse + 0.15;
  cardGlow.material.opacity = 0.7 * pulse + 0.2;

  hover.x += (hover.tx - hover.x) * 0.06;
  hover.y += (hover.ty - hover.y) * 0.06;
  cardGroup.rotation.y = hover.x * 0.12;
  cardGroup.rotation.x = hover.y * 0.10;

  renderer.render(scene, camera);
}
renderer.compile(scene, camera);
stage.classList.add('ready');
if (stage.parentElement) stage.parentElement.classList.add('ready');
tick();
}

try { initGlobe(); }
catch (err){ console.error('WebGL init failed', err); document.documentElement.classList.add('nogl'); }
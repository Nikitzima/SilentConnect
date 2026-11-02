/* =========================================================================
   SilentConnect Background WebGL Engine:
   Volumetric Raycast Emerald Beam + Subtle Topographic Contours
   - Mobile / Touch: Renders the exact volumetric shader into the canvas buffer
     without running a 60fps loop during scroll -> 0% GPU load & 120 FPS checkout!
   - Desktop: Full 120 FPS damped pointer tracking, pauses when scrolled deep.
   ========================================================================= */
(function () {
  const canvas = document.getElementById('bg');
  if (!canvas) return;
  const gl = canvas.getContext('webgl', { alpha: false, antialias: false, depth: false, powerPreference: 'low-power', preserveDrawingBuffer: true });
  if (!gl) { document.documentElement.classList.add('no-webgl'); return; }

  const VERT = 'attribute vec2 p; void main(){ gl_Position = vec4(p, 0., 1.); }';
  const FRAG = `
    #ifdef GL_ES
    precision highp float;
    #endif

    uniform vec2  uRes;
    uniform float uTime;
    uniform float uFade;
    uniform vec2  uMouse;

    float hash(vec2 p) {
      p = fract(p * vec2(234.34, 435.345));
      p += dot(p, p + 34.23);
      return fract(p.x * p.y);
    }

    float noise(vec2 p) {
      vec2 i = floor(p);
      vec2 f = fract(p);
      vec2 u = f * f * (3.0 - 2.0 * f);
      return mix(
        mix(hash(i + vec2(0.0, 0.0)), hash(i + vec2(1.0, 0.0)), u.x),
        mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x),
        u.y
      );
    }

    const mat2 m2 = mat2(0.8, -0.6, 0.6, 0.8);
    float fbm(vec2 p) {
      float f = 0.0;
      float amp = 0.5;
      for (int i = 0; i < 3; i++) {
        f += amp * noise(p);
        p = m2 * p * 2.02;
        amp *= 0.5;
      }
      return f;
    }

    float calcBeam(vec2 uv, vec2 origin, float angleOffset, float timeOffset) {
      vec2 toLight = uv - origin;
      float dist = length(toLight);
      float angle = atan(toLight.y, toLight.x);

      float targetAngle = -1.68 + angleOffset;
      float angleDiff = abs(angle - targetAngle);
      if (angleDiff > 3.14159265) angleDiff = 6.2831853 - angleDiff;

      float cone = smoothstep(1.18, 0.04, angleDiff);
      cone = cone * cone;

      float falloff = exp(-dist * 1.48);

      vec2 flowUv = vec2(angle * 3.8, dist * 2.1 - (uTime + timeOffset) * 0.08);
      float flowNoise = fbm(flowUv * 2.0);
      float breathing = 0.94 + 0.06 * sin(uTime * 0.65 + timeOffset);

      return cone * falloff * (0.78 + 0.42 * flowNoise) * breathing;
    }

    void main() {
      vec2 screenUv = gl_FragCoord.xy / uRes;
      vec2 aspect = vec2(uRes.x / uRes.y, 1.0);
      vec2 uv = (screenUv - 0.5) * aspect;

      vec3 col = vec3(0.0235, 0.0275, 0.0353);

      vec2 origin = vec2(0.08 * aspect.x, 0.54) + vec2(uMouse.x * 0.09, uMouse.y * 0.045);
      float disp = 0.028;
      float bR = calcBeam(uv, origin, -disp, 0.0);
      float bG = calcBeam(uv, origin, 0.0, 0.04);
      float bB = calcBeam(uv, origin, disp * 1.2, 0.08);

      vec3 colDeep = vec3(0.020, 0.588, 0.412);
      vec3 colEdge = vec3(0.063, 0.725, 0.506);
      vec3 colCore = vec3(0.204, 0.827, 0.600);

      vec3 beam = colDeep * bR * 0.32 + colEdge * bG * 0.78 + colCore * bB * 0.65;
      float coreFlare = exp(-length(uv - origin) * 3.6) * 0.48;
      beam += colCore * coreFlare * 0.36;

      col += beam * 0.44 * uFade;

      float d2 = length((screenUv - vec2(0.08, 0.14)) * vec2(0.9, 1.2));
      col += vec3(0.035, 0.075, 0.095) * smoothstep(0.85, 0.0, d2) * 0.24 * uFade;

      float t = uTime * 0.028;
      vec2 q = vec2(fbm(uv * 1.25 + vec2(t, -t * 0.7)), fbm(uv * 1.25 + vec2(-t * 0.8, t) + 5.2));
      float n = fbm(uv * 1.05 + q * 1.1 + uMouse * 0.05);
      float iso = abs(fract(n * 6.5) - 0.5);
      float line = 1.0 - smoothstep(0.0, 0.032, iso - 0.468);
      float mask = smoothstep(0.18, 0.94, screenUv.y) * (0.25 + 0.75 * clamp(bG * 1.8, 0.0, 1.0));
      col += vec3(0.45, 0.92, 0.74) * line * mask * 0.042 * uFade;

      float vig = smoothstep(1.28, 0.32, length((screenUv - 0.5) * vec2(1.05, 1.0)));
      col *= mix(0.76, 1.0, vig);
      col += (hash(gl_FragCoord.xy + fract(uTime)) - 0.5) / 255.0;

      gl_FragColor = vec4(col, 1.0);
    }
  `;

  function sh(type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) return null;
    return s;
  }

  const vs = sh(gl.VERTEX_SHADER, VERT);
  const fs = sh(gl.FRAGMENT_SHADER, FRAG);
  if (!vs || !fs) { document.documentElement.classList.add('no-webgl'); return; }

  const prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  gl.useProgram(prog);

  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, 'p');
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  const uRes = gl.getUniformLocation(prog, 'uRes');
  const uTime = gl.getUniformLocation(prog, 'uTime');
  const uFade = gl.getUniformLocation(prog, 'uFade');
  const uMouse = gl.getUniformLocation(prog, 'uMouse');

  const isMobile = matchMedia('(max-width: 860px)').matches || ('ontouchstart' in window && innerWidth <= 900);
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const SCALE = isMobile ? 0.42 : 0.55;

  let mx = 0, my = 0, tx = 0, ty = 0;
  let raf = 0, t0 = performance.now(), last = t0;

  function renderOnce(timeSec, fadeVal) {
    gl.uniform1f(uTime, timeSec);
    gl.uniform1f(uFade, fadeVal);
    gl.uniform2f(uMouse, mx, my);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  }

  function resize() {
    const w = Math.max(2, Math.round(innerWidth * SCALE));
    const h = Math.max(2, Math.round(innerHeight * SCALE));
    canvas.width = w;
    canvas.height = h;
    gl.viewport(0, 0, w, h);
    gl.uniform2f(uRes, w, h);
    renderOnce(12.0, 0.92);
  }
  addEventListener('resize', resize, { passive: true });
  resize();

  // На мобильных устройствах оставляем отрисованный кадр шейдера без 60fps цикла — 0% нагрузки на GPU при скролле чекаута!
  if (isMobile || reduce) {
    window.__bgReady = true;
    return;
  }

  addEventListener('pointermove', e => {
    tx = (e.clientX / innerWidth) * 2.0 - 1.0;
    ty = 1.0 - (e.clientY / innerHeight) * 2.0;
  }, { passive: true });

  function frame(now) {
    const dt = Math.min((now - last) / 1000, 0.1);
    last = now;
    if (scrollY < 900) {
      const decay = 1.0 - Math.exp(-8.5 * dt);
      mx += (tx - mx) * decay;
      my += (ty - my) * decay;
      const fade = 1.0 - 0.55 * Math.min(1.0, scrollY / 1300);
      renderOnce((now - t0) / 1000, fade);
    }
    raf = requestAnimationFrame(frame);
  }
  function start() { if (!raf) { last = performance.now(); raf = requestAnimationFrame(frame); } }
  function stop() { cancelAnimationFrame(raf); raf = 0; }
  document.addEventListener('visibilitychange', () => (document.hidden ? stop() : start()));
  start();
  window.__bgReady = true;
})();
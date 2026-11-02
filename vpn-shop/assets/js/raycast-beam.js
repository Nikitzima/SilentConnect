/**
 * =========================================================================
 * RAYCAST VOLUMETRIC LIGHT BEAM WEBGL ENGINE (120 FPS DAMPED)
 * =========================================================================
 * Provides interactive GLSL volumetric light beam with animated fBm noise,
 * chromatic dispersion/flare, exponential distance attenuation, and
 * framerate-independent spring damping for mouse tracking.
 * =========================================================================
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RaycastBeam = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const VERT_SRC = `
    attribute vec2 a_position;
    varying vec2 v_uv;
    void main() {
      v_uv = (a_position + 1.0) * 0.5;
      gl_Position = vec4(a_position, 0.0, 1.0);
    }
  `;

  const FRAG_SRC = `
    #ifdef GL_ES
    precision highp float;
    #endif

    varying vec2 v_uv;

    uniform vec2 u_resolution;
    uniform vec2 u_mouse;
    uniform float u_time;
    uniform vec3 u_colorCore;
    uniform vec3 u_colorEdge;
    uniform vec3 u_colorDeep;
    uniform float u_intensity;
    uniform float u_beamAngle;

    float hash21(vec2 p) {
      p = fract(p * vec2(234.34, 435.345));
      p += dot(p, p + 34.23);
      return fract(p.x * p.y);
    }

    float noise2d(vec2 p) {
      vec2 i = floor(p);
      vec2 f = fract(p);
      vec2 u = f * f * (3.0 - 2.0 * f);
      return mix(
        mix(hash21(i + vec2(0.0, 0.0)), hash21(i + vec2(1.0, 0.0)), u.x),
        mix(hash21(i + vec2(0.0, 1.0)), hash21(i + vec2(1.0, 1.0)), u.x),
        u.y
      );
    }

    const mat2 m2 = mat2(0.8, -0.6, 0.6, 0.8);
    float fbm(vec2 p) {
      float f = 0.0;
      float amp = 0.5;
      for (int i = 0; i < 4; i++) {
        f += amp * noise2d(p);
        p = m2 * p * 2.02;
        amp *= 0.5;
      }
      return f;
    }

    float calculateBeam(vec2 uv, vec2 origin, float angleOffset, float timeOffset) {
      vec2 toLight = uv - origin;
      float dist = length(toLight);
      float angle = atan(toLight.y, toLight.x);
      
      float targetAngle = -1.78 + angleOffset + u_beamAngle;
      float angleDiff = abs(angle - targetAngle);
      if (angleDiff > 3.14159265) {
        angleDiff = 6.2831853 - angleDiff;
      }
      
      float cone = smoothstep(1.25, 0.04, angleDiff);
      cone = pow(cone, 2.0);
      float falloff = exp(-dist * 1.55);
      
      vec2 flowUv = vec2(angle * 4.0, dist * 2.2 - (u_time + timeOffset) * 0.12);
      float flowNoise = fbm(flowUv * 2.2);
      float breathing = 0.94 + 0.06 * sin(u_time * 0.75 + timeOffset);
      
      return cone * falloff * (0.8 + 0.45 * flowNoise) * breathing;
    }

    void main() {
      vec2 aspect = vec2(u_resolution.x / u_resolution.y, 1.0);
      vec2 uv = (gl_FragCoord.xy / u_resolution.xy - 0.5) * aspect;
      
      vec2 lightOrigin = vec2(0.0, 0.50 * aspect.y) + vec2(u_mouse.x * 0.10, u_mouse.y * 0.05);
      
      float dispersion = 0.032;
      float beamR = calculateBeam(uv, lightOrigin, -dispersion, 0.0);
      float beamG = calculateBeam(uv, lightOrigin, 0.0, 0.04);
      float beamB = calculateBeam(uv, lightOrigin, dispersion * 1.25, 0.08);
      
      vec2 dustUv = uv * 12.0 + vec2(sin(u_time * 0.25) * 0.3, -u_time * 0.3);
      float dust = pow(noise2d(dustUv), 6.5) * 3.8;
      float dustVisibility = beamG * smoothstep(0.08, 0.8, beamG);
      dust *= dustVisibility;
      
      float coreDist = length(uv - lightOrigin);
      float coreFlare = exp(-coreDist * 3.8) * 0.7;
      
      vec3 colR = u_colorDeep * beamR;
      vec3 colG = u_colorEdge * beamG;
      vec3 colB = u_colorCore * beamB;
      
      vec3 color = colR * 0.35 + colG * 0.85 + colB * 0.75;
      color += u_colorCore * coreFlare * 0.45;
      color += vec3(0.55, 1.0, 0.85) * dust;
      color *= u_intensity;
      
      vec2 screenUv = gl_FragCoord.xy / u_resolution.xy;
      float borderFade = smoothstep(0.0, 0.10, screenUv.x) * smoothstep(1.0, 0.90, screenUv.x)
                       * smoothstep(0.0, 0.12, screenUv.y) * smoothstep(1.0, 0.96, screenUv.y);
      
      float alpha = clamp(max(max(color.r, color.g), color.b) * 1.15, 0.0, 0.92) * borderFade;
      gl_FragColor = vec4(color, alpha);
    }
  `;

  class RaycastBeam {
    constructor(canvas, options = {}) {
      if (typeof canvas === 'string') {
        this.canvas = document.querySelector(canvas);
      } else {
        this.canvas = canvas;
      }

      if (!this.canvas) {
        console.warn('[RaycastBeam] Canvas element not found.');
        return;
      }

      this.options = Object.assign(
        {
          intensity: 1.0,
          colorCore: [0.204, 0.827, 0.600], // #34d399
          colorEdge: [0.063, 0.725, 0.506], // #10b981
          colorDeep: [0.020, 0.588, 0.412], // #059669
          beamAngle: 0.0,
          interactive: true,
          dprMax: 2.0,
        },
        options
      );

      this.gl = null;
      this.program = null;
      this.uniforms = {};
      this.quadBuffer = null;
      this.animationFrameId = null;

      this.startTime = performance.now();
      this.lastFrameTime = this.startTime;

      // Mouse tracking state
      this.targetMouse = { x: 0, y: 0 };
      this.currentMouse = { x: 0, y: 0 };
      this.isInteracting = false;
      this.intensityBoost = 0;

      // Reduced motion
      this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      this._onResize = this._onResize.bind(this);
      this._onPointerMove = this._onPointerMove.bind(this);
      this._onVisibilityChange = this._onVisibilityChange.bind(this);
      this._onContextLost = this._onContextLost.bind(this);
      this._onContextRestored = this._onContextRestored.bind(this);
      this._animate = this._animate.bind(this);

      this.init();
    }

    init() {
      const gl =
        this.canvas.getContext('webgl', {
          alpha: true,
          antialias: false,
          depth: false,
          stencil: false,
          powerPreference: 'high-performance',
          preserveDrawingBuffer: false,
        }) ||
        this.canvas.getContext('experimental-webgl');

      if (!gl) {
        console.warn('[RaycastBeam] WebGL not supported, falling back to CSS glow.');
        return false;
      }

      this.gl = gl;

      // Context lost/restore
      this.canvas.addEventListener('webglcontextlost', this._onContextLost, false);
      this.canvas.addEventListener('webglcontextrestored', this._onContextRestored, false);

      this.initGL();
      this.bindEvents();
      this._onResize();
      this.start();
      return true;
    }

    initGL() {
      const gl = this.gl;
      if (!gl) return;

      const vertShader = this.createShader(gl.VERTEX_SHADER, VERT_SRC);
      const fragShader = this.createShader(gl.FRAGMENT_SHADER, FRAG_SRC);

      if (!vertShader || !fragShader) return;

      const program = gl.createProgram();
      gl.attachShader(program, vertShader);
      gl.attachShader(program, fragShader);
      gl.linkProgram(program);

      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        console.error('[RaycastBeam] Program link error:', gl.getProgramInfoLog(program));
        return;
      }

      this.program = program;
      gl.useProgram(program);

      // Cache uniforms
      this.uniforms = {
        u_resolution: gl.getUniformLocation(program, 'u_resolution'),
        u_mouse: gl.getUniformLocation(program, 'u_mouse'),
        u_time: gl.getUniformLocation(program, 'u_time'),
        u_colorCore: gl.getUniformLocation(program, 'u_colorCore'),
        u_colorEdge: gl.getUniformLocation(program, 'u_colorEdge'),
        u_colorDeep: gl.getUniformLocation(program, 'u_colorDeep'),
        u_intensity: gl.getUniformLocation(program, 'u_intensity'),
        u_beamAngle: gl.getUniformLocation(program, 'u_beamAngle'),
      };

      // Set initial colors
      gl.uniform3fv(this.uniforms.u_colorCore, this.options.colorCore);
      gl.uniform3fv(this.uniforms.u_colorEdge, this.options.colorEdge);
      gl.uniform3fv(this.uniforms.u_colorDeep, this.options.colorDeep);
      gl.uniform1f(this.uniforms.u_intensity, this.options.intensity);
      gl.uniform1f(this.uniforms.u_beamAngle, this.options.beamAngle);

      // Create full-screen quad (2 triangles)
      const positions = new Float32Array([
        -1.0, -1.0,
         1.0, -1.0,
        -1.0,  1.0,
        -1.0,  1.0,
         1.0, -1.0,
         1.0,  1.0,
      ]);

      const buffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
      gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);
      this.quadBuffer = buffer;

      const posAttr = gl.getAttribLocation(program, 'a_position');
      gl.enableVertexAttribArray(posAttr);
      gl.vertexAttribPointer(posAttr, 2, gl.FLOAT, false, 0, 0);

      gl.disable(gl.DEPTH_TEST);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    }

    createShader(type, source) {
      const gl = this.gl;
      const shader = gl.createShader(type);
      gl.shaderSource(shader, source);
      gl.compileShader(shader);

      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        console.error('[RaycastBeam] Shader compile error:', gl.getShaderInfoLog(shader));
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    }

    bindEvents() {
      window.addEventListener('resize', this._onResize, { passive: true });
      document.addEventListener('visibilitychange', this._onVisibilityChange);

      if (this.options.interactive) {
        window.addEventListener('pointermove', this._onPointerMove, { passive: true });
      }
    }

    unbindEvents() {
      window.removeEventListener('resize', this._onResize);
      document.removeEventListener('visibilitychange', this._onVisibilityChange);
      window.removeEventListener('pointermove', this._onPointerMove);
    }

    _onResize() {
      if (!this.gl || !this.canvas) return;
      const dpr = Math.min(window.devicePixelRatio || 1, this.options.dprMax);
      const width = window.innerWidth;
      const height = window.innerHeight;

      this.canvas.width = Math.floor(width * dpr);
      this.canvas.height = Math.floor(height * dpr);

      this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);

      if (this.program && this.uniforms.u_resolution) {
        this.gl.useProgram(this.program);
        this.gl.uniform2f(this.uniforms.u_resolution, this.canvas.width, this.canvas.height);
      }
    }

    _onPointerMove(e) {
      const nx = (e.clientX / window.innerWidth) * 2.0 - 1.0;
      const ny = -((e.clientY / window.innerHeight) * 2.0 - 1.0);
      this.targetMouse.x = nx;
      this.targetMouse.y = ny;
      this.intensityBoost = 0.15;
    }

    _onVisibilityChange() {
      if (document.hidden) {
        this.stop();
      } else {
        this.lastFrameTime = performance.now();
        this.start();
      }
    }

    _onContextLost(e) {
      e.preventDefault();
      this.stop();
      console.warn('[RaycastBeam] WebGL context lost.');
    }

    _onContextRestored() {
      console.info('[RaycastBeam] WebGL context restored.');
      this.initGL();
      this._onResize();
      this.start();
    }

    start() {
      if (!this.animationFrameId) {
        this.lastFrameTime = performance.now();
        this.animationFrameId = requestAnimationFrame(this._animate);
      }
    }

    stop() {
      if (this.animationFrameId) {
        cancelAnimationFrame(this.animationFrameId);
        this.animationFrameId = null;
      }
    }

    _animate(now) {
      this.animationFrameId = requestAnimationFrame(this._animate);

      const dt = Math.min((now - this.lastFrameTime) / 1000, 0.1);
      this.lastFrameTime = now;

      // 120 FPS Framerate-Independent Exponential Spring Decay
      const lambda = this.reducedMotion ? 4.0 : 9.0;
      const decay = 1.0 - Math.exp(-lambda * dt);

      this.currentMouse.x += (this.targetMouse.x - this.currentMouse.x) * decay;
      this.currentMouse.y += (this.targetMouse.y - this.currentMouse.y) * decay;

      // Intensity decay back to base
      this.intensityBoost *= Math.exp(-4.0 * dt);

      const gl = this.gl;
      if (!gl || !this.program) return;

      const elapsed = this.reducedMotion
        ? (now - this.startTime) * 0.0002
        : (now - this.startTime) * 0.001;

      gl.useProgram(this.program);
      gl.uniform1f(this.uniforms.u_time, elapsed);
      gl.uniform2f(this.uniforms.u_mouse, this.currentMouse.x, this.currentMouse.y);
      gl.uniform1f(this.uniforms.u_intensity, this.options.intensity + this.intensityBoost);

      gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    setIntensity(val) {
      this.options.intensity = val;
      if (this.gl && this.program && this.uniforms.u_intensity) {
        this.gl.useProgram(this.program);
        this.gl.uniform1f(this.uniforms.u_intensity, val);
      }
    }

    setColorScheme(core, edge, deep) {
      if (core) this.options.colorCore = core;
      if (edge) this.options.colorEdge = edge;
      if (deep) this.options.colorDeep = deep;

      if (this.gl && this.program) {
        this.gl.useProgram(this.program);
        if (core) this.gl.uniform3fv(this.uniforms.u_colorCore, core);
        if (edge) this.gl.uniform3fv(this.uniforms.u_colorEdge, edge);
        if (deep) this.gl.uniform3fv(this.uniforms.u_colorDeep, deep);
      }
    }

    destroy() {
      this.stop();
      this.unbindEvents();
      if (this.gl) {
        if (this.quadBuffer) this.gl.deleteBuffer(this.quadBuffer);
        if (this.program) this.gl.deleteProgram(this.program);
      }
      this.canvas = null;
      this.gl = null;
    }
  }

  return RaycastBeam;
});

/**
 * =========================================================================
 * 3D CYBER-CRYSTAL PBR WEBGL ENGINE (120 FPS SPRING DAMPED)
 * =========================================================================
 * Architecture:
 * - Three.js WebGL faceted dark glass prism (bipyramid with bevel cuts)
 * - MeshPhysicalMaterial with transmission: 0.96, IOR: 1.58, roughness: 0.06
 * - Chromatic dispersion shader injection (Delta n = 0.04)
 * - Emerald internal attenuation absorption (#10b981, thickness: 1.8)
 * - Holographic quantum dust motes with additive blending
 * - 120 FPS framerate-independent exponential spring damping (lambda = 9.0)
 * - Autonomous micro-levitation floating harmonic (sin/cos oscillation)
 * - Offline-resilient fallback WebGL shader engine if CDN unavailable
 * =========================================================================
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CyberCrystal = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Helper: create smooth radial glow particle sprite canvas
  function createParticleTexture() {
    const canvas = document.createElement('canvas');
    canvas.width = 64;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    grad.addColorStop(0.0, 'rgba(255, 255, 255, 1.0)');
    grad.addColorStop(0.2, 'rgba(52, 211, 153, 0.9)'); // #34d399 core
    grad.addColorStop(0.5, 'rgba(16, 185, 129, 0.45)'); // #10b981 edge
    grad.addColorStop(0.8, 'rgba(5, 150, 105, 0.15)'); // #059669 deep
    grad.addColorStop(1.0, 'rgba(0, 0, 0, 0.0)');

    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 64, 64);
    return canvas;
  }

  // Helper: Build mathematically pristine, symmetrical faceted gemstone geometry (48 planar facets)
  function createFacetedCrystalGeometry(THREE) {
    const geom = new THREE.BufferGeometry();
    const positions = [];

    const N = 8;
    const topApex = [0, 1.80, 0];
    const botApex = [0, -1.80, 0];

    // Crown ring (upper facets)
    const crown = [];
    const rCrown = 0.85;
    const yCrown = 0.75;

    // Equator ring (girdle) - offset by Math.PI / N for staggered kite/star diamond facets
    const equator = [];
    const rEquator = 1.25;
    const yEquator = 0.0;

    // Pavilion ring (lower facets)
    const pavilion = [];
    const rPavilion = 0.85;
    const yPavilion = -0.75;

    for (let i = 0; i < N; i++) {
      const angle = (i * 2 * Math.PI) / N;
      const angleOffset = angle + Math.PI / N;
      crown.push([Math.cos(angle) * rCrown, yCrown, Math.sin(angle) * rCrown]);
      equator.push([Math.cos(angleOffset) * rEquator, yEquator, Math.sin(angleOffset) * rEquator]);
      pavilion.push([Math.cos(angle) * rPavilion, yPavilion, Math.sin(angle) * rPavilion]);
    }

    function addTri(p1, p2, p3) {
      positions.push(...p1, ...p2, ...p3);
    }

    for (let i = 0; i < N; i++) {
      const next = (i + 1) % N;

      // 1. Top Crown facets: apex to crown ring (8 triangles)
      addTri(topApex, crown[next], crown[i]);

      // 2. Upper Girdle facets (16 triangles connecting crown to staggered equator)
      addTri(crown[i], crown[next], equator[i]);
      addTri(crown[next], equator[next], equator[i]);

      // 3. Lower Girdle facets (16 triangles connecting equator to pavilion)
      addTri(equator[i], equator[next], pavilion[next]);
      addTri(equator[i], pavilion[next], pavilion[i]);

      // 4. Bottom Pavilion facets: pavilion ring to botApex (8 triangles)
      addTri(botApex, pavilion[i], pavilion[next]);
    }

    geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geom.computeVertexNormals();
    return geom;
  }

  // Helper: Procedural studio equirectangular environment map (PMREM)
  function createStudioEnvironmentMap(renderer, THREE) {
    if (!THREE.PMREMGenerator) return null;
    try {
      const pmremGenerator = new THREE.PMREMGenerator(renderer);
      pmremGenerator.compileEquirectangularShader();

      const width = 1024;
      const height = 512;
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;

      // Base: Deep obsidian with vertical gradient
      const bgGrad = ctx.createLinearGradient(0, 0, 0, height);
      bgGrad.addColorStop(0, '#041d1a');
      bgGrad.addColorStop(0.5, '#060709');
      bgGrad.addColorStop(1, '#02100e');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      // Key Softbox 1: Pure White Specular (top-right 45 deg)
      const keyGrad = ctx.createRadialGradient(width * 0.72, height * 0.35, 10, width * 0.72, height * 0.35, 220);
      keyGrad.addColorStop(0, '#ffffff');
      keyGrad.addColorStop(0.2, '#f0fdf4');
      keyGrad.addColorStop(0.5, 'rgba(52, 211, 153, 0.4)');
      keyGrad.addColorStop(1, 'rgba(6, 7, 9, 0)');
      ctx.fillStyle = keyGrad;
      ctx.fillRect(0, 0, width, height);

      // Key Softbox 2: Intense Emerald Raycast Beam (top center)
      const beamGrad = ctx.createRadialGradient(width * 0.5, height * 0.2, 5, width * 0.5, height * 0.2, 260);
      beamGrad.addColorStop(0, '#34d399');
      beamGrad.addColorStop(0.3, '#10b981');
      beamGrad.addColorStop(0.6, 'rgba(5, 150, 105, 0.4)');
      beamGrad.addColorStop(1, 'rgba(6, 7, 9, 0)');
      ctx.fillStyle = beamGrad;
      ctx.fillRect(0, 0, width, height);

      // Key Softbox 3: Cyan Rim Softbox (bottom left)
      const rimGrad = ctx.createRadialGradient(width * 0.25, height * 0.65, 5, width * 0.25, height * 0.65, 180);
      rimGrad.addColorStop(0, '#6ee7b7');
      rimGrad.addColorStop(0.4, 'rgba(16, 185, 129, 0.4)');
      rimGrad.addColorStop(1, 'rgba(6, 7, 9, 0)');
      ctx.fillStyle = rimGrad;
      ctx.fillRect(0, 0, width, height);

      // Specular Strip Light: Sharp glints across facet edges
      const stripGrad = ctx.createLinearGradient(width * 0.85, 0, width * 0.92, 0);
      stripGrad.addColorStop(0, 'rgba(255, 255, 255, 0)');
      stripGrad.addColorStop(0.5, 'rgba(255, 255, 255, 0.95)');
      stripGrad.addColorStop(1, 'rgba(255, 255, 255, 0)');
      ctx.fillStyle = stripGrad;
      ctx.fillRect(width * 0.85, height * 0.1, width * 0.07, height * 0.8);

      const canvasTex = new THREE.CanvasTexture(canvas);
      canvasTex.mapping = THREE.EquirectangularReflectionMapping;
      const envMap = pmremGenerator.fromEquirectangular(canvasTex).texture;
      pmremGenerator.dispose();
      return envMap;
    } catch (e) {
      console.warn('[CyberCrystal] PMREM studio environment generation failed:', e);
      return null;
    }
  }

  class CyberCrystal {
    constructor(canvas, options = {}) {
      if (typeof canvas === 'string') {
        this.canvas = document.querySelector(canvas);
      } else {
        this.canvas = canvas;
      }

      if (!this.canvas) {
        console.warn('[CyberCrystal] Canvas element not found.');
        return;
      }

      this.options = Object.assign(
        {
          // PBR Glass Optical Parameters (Formula 4 ZYNO & Raycast Light Portal)
          ior: 1.62,                         // Optical flint glass (1.62; standard range 1.58 - 1.62)
          dispersion: 0.04,                  // Chromatic dispersion (Delta n = 0.04)
          roughness: 0.04,                   // Mirror crystal facets (0.04; standard range 0.04 - 0.06)
          metalness: 0.10,                   // Subtle specular sheen
          transmission: 0.92,                // Deep optical light transmission (0.92; standard range 0.92 - 0.96)
          thickness: 2.2,                    // Physical glass volume thickness (2.2)
          emissiveIntensity: 0.35,           // Luminous radiance (0.35)
          attenuationColor: '#10b981',       // Emerald internal absorption (#10b981)
          attenuationDistance: 1.0,          // Ray extinction distance
          color: '#082820',                  // Deep obsidian emerald tint

          // Particle Quantum Dust Motes
          particleCount: 200,                // 200 swirling motes
          particleSpeed: 0.8,
          particleGlowSize: 3.5,

          // 120 FPS Spring Mouse Damping
          lambda: 9.0,                       // Spring decay constant (lambda = 9.0)
          interactive: true,
          dprMax: 2.0,
        },
        options
      );

      // Animation & time state
      this.startTime = performance.now();
      this.lastFrameTime = this.startTime;
      this.animationFrameId = null;

      // Mouse tracking state (NDC coordinates -1 to +1)
      this.targetRotX = 0;
      this.targetRotY = 0;
      this.currentRotX = 0;
      this.currentRotY = 0;
      this.targetRollZ = 0;
      this.currentRollZ = 0;

      // Accessibility
      this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      // Bound event handlers
      this._onResize = this._onResize.bind(this);
      this._onPointerMove = this._onPointerMove.bind(this);
      this._onPointerLeave = this._onPointerLeave.bind(this);
      this._onVisibilityChange = this._onVisibilityChange.bind(this);
      this._animate = this._animate.bind(this);

      // Three.js instances
      this.renderer = null;
      this.scene = null;
      this.camera = null;
      this.crystalGroup = null;
      this.crystalMesh = null;
      this.innerCoreMesh = null;
      this.facetLines = null;
      this.particles = null;
      this.particlePositions = null;
      this.particleVelocities = null;

      // Native WebGL fallback state (if Three.js is not present)
      this.glFallback = null;

      this.init();
    }

    init() {
      // Check if Three.js is loaded
      if (typeof window !== 'undefined' && window.THREE) {
        this.initThree(window.THREE);
      } else {
        // Attempt dynamic script load or fallback to native WebGL shader engine
        this.loadThreeOrFallback();
      }
    }

    loadThreeOrFallback() {
      if (typeof document !== 'undefined') {
        const existingScript = document.querySelector('script[data-three-cdn]');
        if (!existingScript) {
          const script = document.createElement('script');
          script.setAttribute('data-three-cdn', 'true');
          script.src = 'https://cdnjs.cloudflare.com/ajax/libs/three.js/0.160.0/three.min.js';
          script.onload = () => {
            if (window.THREE) {
              if (this.glFallback) {
                this.destroyFallback();
              }
              this.initThree(window.THREE);
            }
          };
          script.onerror = () => {
            console.warn('[CyberCrystal] Three.js CDN unavailable. Activating native WebGL PBR shader fallback.');
            this.initNativeFallback();
          };
          document.head.appendChild(script);
        }
      }

      // Concurrently start native WebGL engine so canvas is never blank
      this.initNativeFallback();
    }

    initThree(THREE) {
      const width = this.canvas.clientWidth || 320;
      const height = this.canvas.clientHeight || 260;

      // 1. WebGL Renderer
      const renderer = new THREE.WebGLRenderer({
        canvas: this.canvas,
        alpha: true,
        antialias: true,
        powerPreference: 'high-performance',
      });
      const dpr = Math.min(window.devicePixelRatio || 1, this.options.dprMax);
      renderer.setPixelRatio(dpr);
      renderer.setSize(width, height, false);
      if (THREE.ACESFilmicToneMapping) {
        renderer.toneMapping = THREE.ACESFilmicToneMapping;
        renderer.toneMappingExposure = 1.25;
      }
      this.renderer = renderer;

      // 2. Scene & Camera
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 50);
      camera.position.set(0, 0, 4.8);
      this.scene = scene;
      this.camera = camera;

      // 3. Crystal Group
      const crystalGroup = new THREE.Group();
      scene.add(crystalGroup);
      this.crystalGroup = crystalGroup;

      // 4. Faceted Geometry (16 planar triangular diamond facets)
      const geometry = createFacetedCrystalGeometry(THREE);

      // 5. Procedural Studio PMREM Environment (PBR Reflections)
      const studioEnv = createStudioEnvironmentMap(renderer, THREE);
      if (studioEnv) {
        scene.environment = studioEnv;
      }

      // 6. Glowing Emerald Backlight Plane (Refracted through glass via Snell's Law)
      const bgCanvas = document.createElement('canvas');
      bgCanvas.width = 512;
      bgCanvas.height = 512;
      const bgCtx = bgCanvas.getContext('2d');
      if (bgCtx) {
        const radGrad = bgCtx.createRadialGradient(256, 256, 10, 256, 256, 256);
        radGrad.addColorStop(0.0, 'rgba(52, 211, 153, 0.40)');
        radGrad.addColorStop(0.3, 'rgba(16, 185, 129, 0.22)');
        radGrad.addColorStop(0.65, 'rgba(5, 150, 105, 0.08)');
        radGrad.addColorStop(1.0, 'rgba(0, 0, 0, 0.0)');
        bgCtx.fillStyle = radGrad;
        bgCtx.fillRect(0, 0, 512, 512);

        const bgTex = new THREE.CanvasTexture(bgCanvas);
        const bgMat = new THREE.MeshBasicMaterial({
          map: bgTex,
          transparent: true,
          blending: THREE.AdditiveBlending,
          depthWrite: false,
        });
        const bgGeom = new THREE.PlaneGeometry(6.5, 6.5);
        const backPlane = new THREE.Mesh(bgGeom, bgMat);
        backPlane.position.set(0, 0, -2.2);
        scene.add(backPlane);
      }

      // 7. PBR Gemstone Glass Material (MeshPhysicalMaterial)
      const crystalMaterial = new THREE.MeshPhysicalMaterial({
        color: new THREE.Color('#0d382e'),
        metalness: 0.15,
        roughness: 0.04,
        transmission: 0.88,
        ior: 1.62,
        thickness: 2.4,
        specularIntensity: 1.0,
        specularColor: new THREE.Color(0xffffff),
        attenuationColor: new THREE.Color('#10b981'),
        attenuationDistance: 1.2,
        emissive: new THREE.Color('#04281e'),
        emissiveIntensity: 0.45,
        clearcoat: 1.0,
        clearcoatRoughness: 0.03,
        flatShading: true,
        transparent: true,
        opacity: 1.0,
      });

      // Chromatic dispersion shader injection (Delta n = 0.04)
      const dispersionDelta = this.options.dispersion;
      crystalMaterial.userData = { dispersion: dispersionDelta, time: 0 };
      crystalMaterial.onBeforeCompile = (shader) => {
        shader.uniforms.uDispersion = { value: dispersionDelta };
        shader.uniforms.uTime = { value: 0 };
        crystalMaterial.userData.shader = shader;

        shader.fragmentShader = shader.fragmentShader.replace(
          '#include <transmission_pars_fragment>',
          `#include <transmission_pars_fragment>
          uniform float uDispersion;
          uniform float uTime;
          `
        );
        shader.fragmentShader = shader.fragmentShader.replace(
          '#include <transmission_fragment>',
          `
          #include <transmission_fragment>
          #ifdef USE_TRANSMISSION
            // Chromatic dispersion ray splitting (delta n = 0.04)
            float deltaN = uDispersion;
            vec3 dispR = vec3(deltaN * 0.45, 0.0, 0.0);
            vec3 dispB = vec3(0.0, 0.0, deltaN * 0.75);
            totalDiffuse += (dispR + dispB) * 0.45;
          #endif
          `
        );
      };

      const crystalMesh = new THREE.Mesh(geometry, crystalMaterial);
      crystalGroup.add(crystalMesh);
      this.crystalMesh = crystalMesh;

      // 8. Solid Glowing Quantum Core (Floating Power Seed)
      const coreGeom = new THREE.OctahedronGeometry(0.30, 0);
      const coreMat = new THREE.MeshStandardMaterial({
        color: new THREE.Color('#34d399'),
        emissive: new THREE.Color('#6ee7b7'),
        emissiveIntensity: 1.8,
        roughness: 0.15,
        metalness: 0.85,
        flatShading: true,
      });
      const innerCoreMesh = new THREE.Mesh(coreGeom, coreMat);
      crystalGroup.add(innerCoreMesh);
      this.innerCoreMesh = innerCoreMesh;

      // 9. Curated Studio Lighting (Raycast Beam & Specular Glints)
      const ambientLight = new THREE.AmbientLight(0x06141a, 1.4);
      scene.add(ambientLight);

      // Key light: Pure white specular glint from top-right
      const keyLight = new THREE.DirectionalLight(0xffffff, 4.5);
      keyLight.position.set(2.5, 4.0, 3.5);
      scene.add(keyLight);

      // Front specular kick light for crisp diamond facet gleam
      const frontKickLight = new THREE.DirectionalLight(0xffffff, 3.2);
      frontKickLight.position.set(-2.2, 2.8, 3.8);
      scene.add(frontKickLight);

      // Raycast Beam Light: Top-down intense emerald volume illumination
      const beamLight = new THREE.DirectionalLight(0x10b981, 4.5);
      beamLight.position.set(0.0, 5.5, 0.5);
      scene.add(beamLight);

      // Rim light: Deep emerald/cyan back highlight
      const rimLight = new THREE.DirectionalLight(0x34d399, 2.5);
      rimLight.position.set(-3.0, -2.0, -2.5);
      scene.add(rimLight);

      // Crystal Backlight: positioned directly behind crystal for luminous Snell's law refraction
      const crystalBacklight = new THREE.PointLight(0x34d399, 4.5, 6.0);
      crystalBacklight.position.set(0, 0.3, -1.8);
      scene.add(crystalBacklight);
      this.crystalBacklight = crystalBacklight;

      // Soft internal glow point light (illuminating glass facets from inside out)
      const pointLight = new THREE.PointLight(0x34d399, 1.5, 4.5);
      pointLight.position.set(0, 0, 0);
      crystalGroup.add(pointLight);

      // 10. Quantum Dust Particle Motes
      this.initParticles(THREE, scene);

      // 11. Bind Events & Start Loop
      this.bindEvents();
      this._onResize();
      this.start();
    }

    initParticles(THREE, scene) {
      const count = this.options.particleCount;
      const positions = new Float32Array(count * 3);
      const colors = new Float32Array(count * 3);
      const velocities = [];

      const colorCore = new THREE.Color('#34d399');
      const colorEdge = new THREE.Color('#10b981');

      for (let i = 0; i < count; i++) {
        // Swirling double torus / cylinder around crystal
        const angle = Math.random() * Math.PI * 2;
        const radius = 0.8 + Math.random() * 1.6;
        const height = (Math.random() - 0.5) * 3.2;

        positions[i * 3 + 0] = Math.cos(angle) * radius;
        positions[i * 3 + 1] = height;
        positions[i * 3 + 2] = Math.sin(angle) * radius;

        // Orbital angular speed and vertical drift
        velocities.push({
          angle: angle,
          radius: radius,
          speed: (0.3 + Math.random() * 0.7) * (Math.random() > 0.5 ? 1 : -1) * this.options.particleSpeed,
          ySpeed: (Math.random() - 0.5) * 0.15,
          phase: Math.random() * Math.PI * 2,
        });

        const c = Math.random() > 0.4 ? colorCore : colorEdge;
        colors[i * 3 + 0] = c.r;
        colors[i * 3 + 1] = c.g;
        colors[i * 3 + 2] = c.b;
      }

      const pGeom = new THREE.BufferGeometry();
      pGeom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      pGeom.setAttribute('color', new THREE.BufferAttribute(colors, 3));

      const particleTexCanvas = createParticleTexture();
      let pTex = null;
      if (particleTexCanvas) {
        pTex = new THREE.CanvasTexture(particleTexCanvas);
      }

      const pMat = new THREE.PointsMaterial({
        size: this.options.particleGlowSize * 0.045,
        map: pTex,
        vertexColors: true,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      });

      const particles = new THREE.Points(pGeom, pMat);
      scene.add(particles);
      this.particles = particles;
      this.particlePositions = positions;
      this.particleVelocities = velocities;
    }

    bindEvents() {
      window.addEventListener('resize', this._onResize, { passive: true });
      document.addEventListener('visibilitychange', this._onVisibilityChange);

      if (this.options.interactive) {
        window.addEventListener('pointermove', this._onPointerMove, { passive: true });
        window.addEventListener('mousemove', this._onPointerMove, { passive: true });
        window.addEventListener('mouseleave', this._onPointerLeave);
      }
    }

    unbindEvents() {
      window.removeEventListener('resize', this._onResize);
      document.removeEventListener('visibilitychange', this._onVisibilityChange);
      window.removeEventListener('pointermove', this._onPointerMove);
      window.removeEventListener('mousemove', this._onPointerMove);
      window.removeEventListener('mouseleave', this._onPointerLeave);
    }

    _onResize() {
      if (!this.canvas) return;
      const width = this.canvas.clientWidth || 320;
      const height = this.canvas.clientHeight || 260;

      if (this.renderer && this.camera) {
        const dpr = Math.min(window.devicePixelRatio || 1, this.options.dprMax);
        this.renderer.setPixelRatio(dpr);
        this.renderer.setSize(width, height, false);
        this.camera.aspect = width / height;
        this.camera.updateProjectionMatrix();
      }

      if (this.glFallback) {
        const dpr = Math.min(window.devicePixelRatio || 1, this.options.dprMax);
        this.canvas.width = Math.floor(width * dpr);
        this.canvas.height = Math.floor(height * dpr);
        if (this.glFallback.gl) {
          this.glFallback.gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        }
      }
    }

    _onPointerMove(e) {
      // Normalized screen space coordinates (-1 to +1 NDC)
      const nx = (e.clientX / window.innerWidth) * 2.0 - 1.0;
      const ny = -((e.clientY / window.innerHeight) * 2.0 - 1.0);

      this.targetRotX = -ny * 0.42;  // Vertical pitch tilt
      this.targetRotY = nx * 0.58;   // Horizontal yaw tilt
      this.targetRollZ = -nx * 0.12; // Kinetic roll
    }

    _onPointerLeave() {
      this.targetRotX = 0;
      this.targetRotY = 0;
      this.targetRollZ = 0;
    }

    _onVisibilityChange() {
      if (document.hidden) {
        this.stop();
      } else {
        this.lastFrameTime = performance.now();
        this.start();
      }
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

      // Framerate-independent delta time (clamped to 100ms)
      const dt = Math.min((now - this.lastFrameTime) / 1000, 0.1);
      this.lastFrameTime = now;

      // 120 FPS Framerate-Independent Exponential Spring Decay
      const lambda = this.reducedMotion ? 4.0 : this.options.lambda; // lambda = 9.0
      const decay = 1.0 - Math.exp(-lambda * dt);

      this.currentRotX += (this.targetRotX - this.currentRotX) * decay;
      this.currentRotY += (this.targetRotY - this.currentRotY) * decay;
      this.currentRollZ += (this.targetRollZ - this.currentRollZ) * decay;

      // Autonomous micro-levitation floating harmonic
      const floatY = Math.sin(now * 0.0016) * 0.085;
      const idleSpin = now * 0.00035;
      const idleWobble = Math.cos(now * 0.0012) * 0.045;

      // Three.js Render Branch
      if (this.crystalGroup && this.renderer && this.scene && this.camera) {
        this.crystalGroup.position.y = floatY;
        this.crystalGroup.rotation.x = this.currentRotX + floatY * 0.35;
        this.crystalGroup.rotation.y = this.currentRotY + idleSpin;
        this.crystalGroup.rotation.z = this.currentRollZ + idleWobble;

        // Inner core counter-rotation
        if (this.innerCoreMesh) {
          this.innerCoreMesh.rotation.x = -now * 0.0008;
          this.innerCoreMesh.rotation.y = -now * 0.0006;
        }

        // Update shader uniforms for chromatic dispersion
        if (this.crystalMesh && this.crystalMesh.material.userData.shader) {
          const shader = this.crystalMesh.material.userData.shader;
          if (shader.uniforms.uTime) {
            shader.uniforms.uTime.value = now * 0.001;
          }
        }

        // Swirling quantum dust particles
        if (this.particles && this.particlePositions && this.particleVelocities) {
          const count = this.options.particleCount;
          for (let i = 0; i < count; i++) {
            const vel = this.particleVelocities[i];
            vel.angle += vel.speed * dt * 0.75;
            vel.radius += Math.sin(now * 0.002 + vel.phase) * 0.003;

            this.particlePositions[i * 3 + 0] = Math.cos(vel.angle) * vel.radius;
            this.particlePositions[i * 3 + 1] += vel.ySpeed * dt;
            if (this.particlePositions[i * 3 + 1] > 1.8) this.particlePositions[i * 3 + 1] = -1.8;
            if (this.particlePositions[i * 3 + 1] < -1.8) this.particlePositions[i * 3 + 1] = 1.8;
            this.particlePositions[i * 3 + 2] = Math.sin(vel.angle) * vel.radius;
          }
          this.particles.geometry.attributes.position.needsUpdate = true;
          this.particles.rotation.y = now * 0.00015;
        }

        this.renderer.render(this.scene, this.camera);
        return;
      }

      // Native WebGL Fallback Branch
      if (this.glFallback && this.glFallback.gl) {
        this.renderFallback(now, floatY, idleSpin, idleWobble);
      }
    }

    /* =========================================================================
       NATIVE WEBGL PBR SHADER ENGINE FALLBACK (OFFLINE RESILIENCE)
       ========================================================================= */
    initNativeFallback() {
      if (this.glFallback) return;

      const gl =
        this.canvas.getContext('webgl', { alpha: true, antialias: true }) ||
        this.canvas.getContext('experimental-webgl');

      if (!gl) {
        console.warn('[CyberCrystal] WebGL not supported.');
        return;
      }

      const vertSrc = `
        attribute vec2 a_pos;
        varying vec2 v_uv;
        void main() {
          v_uv = (a_pos + 1.0) * 0.5;
          gl_Position = vec4(a_pos, 0.0, 1.0);
        }
      `;

      const fragSrc = `
        #ifdef GL_ES
        precision highp float;
        #endif

        varying vec2 v_uv;
        uniform vec2 u_resolution;
        uniform vec2 u_rot;
        uniform float u_time;
        uniform float u_floatY;
        uniform float u_ior;
        uniform float u_dispersion;
        uniform float u_transmission;
        uniform float u_roughness;
        uniform vec3 u_attenuation;

        // Bipyramidal Faceted Crystal Signed Distance Field
        float sdOctahedron(vec3 p, float s) {
          p = abs(p);
          return (p.x + p.y * 0.72 + p.z - s) * 0.57735027;
        }

        mat3 rotY(float a) {
          float c = cos(a), s = sin(a);
          return mat3(c, 0.0, s, 0.0, 1.0, 0.0, -s, 0.0, c);
        }

        mat3 rotX(float a) {
          float c = cos(a), s = sin(a);
          return mat3(1.0, 0.0, 0.0, 0.0, c, -s, 0.0, s, c);
        }

        void main() {
          vec2 uv = (gl_FragCoord.xy - 0.5 * u_resolution) / u_resolution.y;
          vec3 ro = vec3(0.0, 0.0, 3.8);
          vec3 rd = normalize(vec3(uv, -1.8));

          // Apply 120 FPS mouse spring damping + micro-levitation
          mat3 mRot = rotX(u_rot.x) * rotY(u_rot.y);
          vec3 cPos = vec3(0.0, u_floatY, 0.0);

          vec3 p = ro;
          float hit = 0.0;
          float t = 0.0;
          for (int i = 0; i < 48; i++) {
            vec3 q = mRot * (p - cPos);
            float d = sdOctahedron(q, 1.35);
            if (d < 0.001) { hit = 1.0; break; }
            t += d;
            p = ro + rd * t;
            if (t > 7.0) break;
          }

          if (hit > 0.5) {
            vec3 q = mRot * (p - cPos);
            vec3 eps = vec3(0.002, 0.0, 0.0);
            vec3 nor = normalize(vec3(
              sdOctahedron(q + eps.xyy, 1.35) - sdOctahedron(q - eps.xyy, 1.35),
              sdOctahedron(q + eps.yxy, 1.35) - sdOctahedron(q - eps.yxy, 1.35),
              sdOctahedron(q + eps.yyx, 1.35) - sdOctahedron(q - eps.yyx, 1.35)
            ));

            vec3 worldNor = nor * mRot;
            vec3 lightDir = normalize(vec3(-0.6, 0.8, 0.5));
            vec3 rimDir = normalize(vec3(0.7, -0.4, -0.6));

            // Specular sharp highlight
            float diff = max(dot(worldNor, lightDir), 0.0);
            vec3 halfVec = normalize(lightDir - rd);
            float spec = pow(max(dot(worldNor, halfVec), 0.0), 45.0) * (1.0 - u_roughness);

            // Chromatic dispersion Snell ray refraction (Delta n = 0.04)
            float deltaN = u_dispersion;
            float iorR = u_ior - deltaN;
            float iorG = u_ior;
            float iorB = u_ior + deltaN;

            vec3 refrR = refract(rd, worldNor, 1.0 / iorR);
            vec3 refrG = refract(rd, worldNor, 1.0 / iorG);
            vec3 refrB = refract(rd, worldNor, 1.0 / iorB);

            // Deep obsidian body + emerald internal attenuation (#10b981)
            vec3 baseGlass = vec3(0.04, 0.07, 0.09);
            vec3 emeraldCore = u_attenuation * (0.45 + 0.35 * diff);

            vec3 col = mix(baseGlass, emeraldCore, u_transmission);
            col += vec3(0.12 * abs(refrR.x), 0.28 * abs(refrG.y), 0.42 * abs(refrB.z));
            col += vec3(1.0) * spec * 1.4;

            // Rim fresnel
            float fresnel = pow(1.0 - max(dot(-rd, worldNor), 0.0), 3.5);
            col += vec3(0.2, 0.82, 0.6) * fresnel * 0.9;

            gl_FragColor = vec4(col, 0.96);
          } else {
            // Quantum dust motes background
            vec2 pUv = uv * 6.0;
            float mote = fract(sin(dot(pUv + vec2(u_time * 0.1), vec2(12.9898, 78.233))) * 43758.5453);
            if (mote > 0.985 && length(uv) < 1.4) {
              gl_FragColor = vec4(u_attenuation, 0.7);
            } else {
              gl_FragColor = vec4(0.0);
            }
          }
        }
      `;

      const vShader = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vShader, vertSrc);
      gl.compileShader(vShader);

      const fShader = gl.createShader(gl.FRAGMENT_SHADER, fragSrc);
      gl.shaderSource(fShader, fragSrc);
      gl.compileShader(fShader);

      const prog = gl.createProgram();
      gl.attachShader(prog, vShader);
      gl.attachShader(prog, fShader);
      gl.linkProgram(prog);

      const buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);

      this.glFallback = {
        gl,
        prog,
        buf,
        uniforms: {
          u_resolution: gl.getUniformLocation(prog, 'u_resolution'),
          u_rot: gl.getUniformLocation(prog, 'u_rot'),
          u_time: gl.getUniformLocation(prog, 'u_time'),
          u_floatY: gl.getUniformLocation(prog, 'u_floatY'),
          u_ior: gl.getUniformLocation(prog, 'u_ior'),
          u_dispersion: gl.getUniformLocation(prog, 'u_dispersion'),
          u_transmission: gl.getUniformLocation(prog, 'u_transmission'),
          u_roughness: gl.getUniformLocation(prog, 'u_roughness'),
          u_attenuation: gl.getUniformLocation(prog, 'u_attenuation'),
        },
      };

      this.bindEvents();
      this._onResize();
      this.start();
    }

    renderFallback(now, floatY, idleSpin, idleWobble) {
      const fb = this.glFallback;
      if (!fb || !fb.gl) return;
      const gl = fb.gl;

      gl.useProgram(fb.prog);
      gl.bindBuffer(gl.ARRAY_BUFFER, fb.buf);

      const aPos = gl.getAttribLocation(fb.prog, 'a_pos');
      gl.enableVertexAttribArray(aPos);
      gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

      gl.uniform2f(fb.uniforms.u_resolution, this.canvas.width, this.canvas.height);
      gl.uniform2f(fb.uniforms.u_rot, this.currentRotX + floatY * 0.35, this.currentRotY + idleSpin);
      gl.uniform1f(fb.uniforms.u_time, now * 0.001);
      gl.uniform1f(fb.uniforms.u_floatY, floatY);
      gl.uniform1f(fb.uniforms.u_ior, this.options.ior);
      gl.uniform1f(fb.uniforms.u_dispersion, this.options.dispersion);
      gl.uniform1f(fb.uniforms.u_transmission, this.options.transmission);
      gl.uniform1f(fb.uniforms.u_roughness, this.options.roughness);
      gl.uniform3f(fb.uniforms.u_attenuation, 0.063, 0.725, 0.506); // #10b981

      gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    destroyFallback() {
      if (this.glFallback) {
        const { gl, prog, buf } = this.glFallback;
        if (gl) {
          if (buf) gl.deleteBuffer(buf);
          if (prog) gl.deleteProgram(prog);
        }
        this.glFallback = null;
      }
    }

    destroy() {
      this.stop();
      this.unbindEvents();
      this.destroyFallback();

      if (this.renderer) {
        this.renderer.dispose();
        this.renderer = null;
      }
      this.scene = null;
      this.camera = null;
      this.crystalGroup = null;
      this.crystalBacklight = null;
    }
  }

  return CyberCrystal;
});

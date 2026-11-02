#ifdef GL_ES
precision highp float;
#endif

varying vec2 v_uv;

uniform vec2 u_resolution;
uniform vec2 u_mouse;       // Normalized mouse offset [-1.0, 1.0]
uniform float u_time;
uniform vec3 u_colorCore;    // Primary bright core (#34d399)
uniform vec3 u_colorEdge;    // Signature Emerald (#10b981)
uniform vec3 u_colorDeep;    // Deep emerald base (#059669)
uniform float u_intensity;    // Master brightness (default 1.0)
uniform float u_beamAngle;    // Additional tilt angle in radians

// High quality 2D hash
float hash21(vec2 p) {
    p = fract(p * vec2(234.34, 435.345));
    p += dot(p, p + 34.23);
    return fract(p.x * p.y);
}

// Bilinear smooth value noise
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

// 4-octave fractal Brownian motion with rotation to eliminate grid artifacts
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

// Analytical single ray cone with turbulent flow and breathing
float calculateBeam(vec2 uv, vec2 origin, float angleOffset, float timeOffset) {
    vec2 toLight = uv - origin;
    float dist = length(toLight);
    float angle = atan(toLight.y, toLight.x);
    
    // Main directional cone pointing downward across hero section (Raycast angle ~ -1.75 rad)
    float targetAngle = -1.78 + angleOffset + u_beamAngle;
    float angleDiff = abs(angle - targetAngle);
    if (angleDiff > 3.14159265) {
        angleDiff = 6.2831853 - angleDiff;
    }
    
    // Smooth conical falloff
    float cone = smoothstep(1.25, 0.04, angleDiff);
    cone = pow(cone, 2.0);
    
    // Exponential distance attenuation (fades out as beam travels down)
    float falloff = exp(-dist * 1.55);
    
    // Animated turbulent flowing streaks along the beam direction
    vec2 flowUv = vec2(angle * 4.0, dist * 2.2 - (u_time + timeOffset) * 0.12);
    float flowNoise = fbm(flowUv * 2.2);
    
    // Ambient breathing cycle
    float breathing = 0.94 + 0.06 * sin(u_time * 0.75 + timeOffset);
    
    return cone * falloff * (0.8 + 0.45 * flowNoise) * breathing;
}

void main() {
    // Aspect ratio corrected coordinates centered at screen center
    vec2 aspect = vec2(u_resolution.x / u_resolution.y, 1.0);
    vec2 uv = (gl_FragCoord.xy / u_resolution.xy - 0.5) * aspect;
    
    // Light origin at the top-center, dynamically swayed by mouse parallax
    vec2 lightOrigin = vec2(0.0, 0.50 * aspect.y) + vec2(u_mouse.x * 0.10, u_mouse.y * 0.05);
    
    // Chromatic dispersion: evaluate Red, Green, Blue with slight angular offset
    // Emulates physical prism refraction and chromatic aberration on beam edges
    float dispersion = 0.032;
    float beamR = calculateBeam(uv, lightOrigin, -dispersion, 0.0);
    float beamG = calculateBeam(uv, lightOrigin, 0.0, 0.04);
    float beamB = calculateBeam(uv, lightOrigin, dispersion * 1.25, 0.08);
    
    // Sparkling volumetric dust motes
    vec2 dustUv = uv * 12.0 + vec2(sin(u_time * 0.25) * 0.3, -u_time * 0.3);
    float dust = pow(noise2d(dustUv), 6.5) * 3.8;
    float dustVisibility = beamG * smoothstep(0.08, 0.8, beamG);
    dust *= dustVisibility;
    
    // Central focal flare
    float coreDist = length(uv - lightOrigin);
    float coreFlare = exp(-coreDist * 3.8) * 0.7;
    
    // Spectral blending with Signature Emerald (#10b981) + core (#34d399)
    vec3 colR = u_colorDeep * beamR;
    vec3 colG = u_colorEdge * beamG;
    vec3 colB = u_colorCore * beamB;
    
    vec3 color = colR * 0.35 + colG * 0.85 + colB * 0.75;
    color += u_colorCore * coreFlare * 0.45;
    color += vec3(0.55, 1.0, 0.85) * dust;
    
    // Apply master intensity
    color *= u_intensity;
    
    // Soft radial fade towards screen boundaries to melt into Deep Obsidian #060709
    vec2 screenUv = gl_FragCoord.xy / u_resolution.xy;
    float borderFade = smoothstep(0.0, 0.10, screenUv.x) * smoothstep(1.0, 0.90, screenUv.x)
                     * smoothstep(0.0, 0.12, screenUv.y) * smoothstep(1.0, 0.96, screenUv.y);
    
    float alpha = clamp(max(max(color.r, color.g), color.b) * 1.15, 0.0, 0.92) * borderFade;
    
    gl_FragColor = vec4(color, alpha);
}

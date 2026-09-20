import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
// Vite publicDir points at ../out — assets live at site root
const OUT_BASE = "/";

/** Site-root URL for a baked palette PNG (always single leading slash). */
function paletteTextureUrl(courseId, materialName) {
  return `${OUT_BASE}textures/palette_cache/${courseId}/${materialName}.png`;
}

/** Palette OBJs bind textures in the viewer; skip MTLLoader map preload (avoids bad URL joins). */
function stripMtlTexturePaths(materialsInfo) {
  for (const info of Object.values(materialsInfo || {})) {
    for (const key of Object.keys(info)) {
      if (key.startsWith("map_")) delete info[key];
    }
  }
}

function buildPaletteMaterial(name, map) {
  const cutout = name.endsWith("_tr");
  return new THREE.ShaderMaterial({
    name,
    uniforms: {
      map: { value: map },
      cutout: { value: cutout ? 1.0 : 0.0 },
    },
    vertexShader: `
      varying vec2 vUv;
      void main() {
        vUv = uv;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `,
    fragmentShader: `
      uniform sampler2D map;
      uniform float cutout;
      varying vec2 vUv;
      void main() {
        vec4 texel = texture2D(map, vUv);
        if (cutout > 0.5 && texel.a < 0.5) discard;
        gl_FragColor = vec4(texel.rgb, 1.0);
      }
    `,
    side: THREE.DoubleSide,
    depthTest: true,
    depthWrite: !cutout,
    transparent: cutout,
  });
}

/**
 * OBJLoader builds one BufferGeometry with a material[] per usemtl change.
 * Exports that emit usemtl every face create 10k+ groups; split into one mesh per material.
 */
function splitMultiMaterialMeshes(object) {
  const toSplit = [];
  object.traverse((child) => {
    if (child.isMesh && Array.isArray(child.material) && child.geometry?.groups?.length) {
      toSplit.push(child);
    }
  });
  for (const mesh of toSplit) {
    const { geometry, material: materials, parent } = mesh;
    const { groups } = geometry;
    const pos = geometry.attributes.position;
    const uv = geometry.attributes.uv;
    const norm = geometry.attributes.normal;
    const buckets = new Map();

    for (const group of groups) {
      const mat = materials[group.materialIndex];
      if (!mat) continue;
      if (!buckets.has(mat)) {
        buckets.set(mat, { positions: [], uvs: [], normals: [] });
      }
      const bucket = buckets.get(mat);
      for (let vi = group.start; vi < group.start + group.count; vi += 1) {
        bucket.positions.push(pos.getX(vi), pos.getY(vi), pos.getZ(vi));
        if (uv) bucket.uvs.push(uv.getX(vi), uv.getY(vi));
        if (norm) bucket.normals.push(norm.getX(vi), norm.getY(vi), norm.getZ(vi));
      }
    }

    const splitRoot = new THREE.Group();
    splitRoot.name = mesh.name || "textured";
    for (const [mat, data] of buckets) {
      const geom = new THREE.BufferGeometry();
      geom.setAttribute("position", new THREE.Float32BufferAttribute(data.positions, 3));
      if (data.uvs.length) geom.setAttribute("uv", new THREE.Float32BufferAttribute(data.uvs, 2));
      if (data.normals.length) geom.setAttribute("normal", new THREE.Float32BufferAttribute(data.normals, 3));
      splitRoot.add(new THREE.Mesh(geom, mat));
    }

    if (parent) {
      parent.add(splitRoot);
      parent.remove(mesh);
    }
    geometry.dispose();
  }
  return object;
}

const CATEGORY_ORDER = ["track", "vehicles", "props", "overview", "other"];

let scene, camera, renderer, controls;
let gridHelper, axesHelper, meshGroup, heightmapMesh;
let meshExtents = null;
let meshPositionsAll = [];
let meshFacesAll = [];
let meshNormalsAll = [];
let meshFaceNormalIndicesAll = [];
let texturedMeshObject = null;
let meshYBounds = { min: -500, max: 500 };
let meshZBounds = { min: -500, max: 500 };
/** Longest axis of the currently framed mesh; drives zoom limits and wheel sensitivity. */
let sceneBounds = { maxDim: 4000 };
let assetIndex = null;
let assetsByCategory = new Map();
let currentAsset = null;
let displayMode = "points";
let manifestTextures = [];
let pointSize = 4;
let meshColor = 0x66ccff;

function vehicleSortKey(asset) {
  const id = asset.id || "";
  const role = asset.role || "";
  if (id.includes("posed_assembly")) return [0, id];
  if (id.includes("core_assembly")) return [1, id];
  if (id.includes("assembly")) return [2, id];
  if (role === "body_shell") return [3, id];
  if (role === "trim" || role === "wheel_or_trim") return [4, id];
  return [5, id];
}

const COURSE_TRACK_ORDER = { desert: 0, forest: 1, mountain: 2, championship: 3 };

function trackSortKey(asset) {
  if (asset.course_id && asset.course_id in COURSE_TRACK_ORDER) {
    const order = COURSE_TRACK_ORDER[asset.course_id];
    const isMainCourse = asset.id === `track_${asset.course_id}`;
    const isSupplement = asset.role === "detached_segment" || asset.parent_course;
    if (isMainCourse) return [-2, order, 0];
    if (isSupplement) return [-2, order, 1];
    return [-2, order, 2];
  }
  if (asset.id === "track_race_combined") return [-1, 0];
  if (asset.id === "track_phase_a") return [0, 0];
  if (asset.id === "track_phase_b") return [0, 1];
  const range = asset.placement_range;
  const start = Array.isArray(range) ? range[0] : 9999;
  const tierRank = asset.tier === "major_geometry" ? 0 : asset.tier === "medium_geometry" ? 1 : 2;
  return [1, start, tierRank];
}

function sortAssets(list) {
  if (!list.length) return [];
  if (list[0].category === "vehicles") {
    return [...list].sort((a, b) => {
      const [ka, ida] = vehicleSortKey(a);
      const [kb, idb] = vehicleSortKey(b);
      return ka - kb || ida.localeCompare(idb) || (b.vertices || 0) - (a.vertices || 0);
    });
  }
  if (list[0].category === "track") {
    return [...list].sort((a, b) => {
      const ka = trackSortKey(a);
      const kb = trackSortKey(b);
      for (let i = 0; i < Math.max(ka.length, kb.length); i += 1) {
        if ((ka[i] ?? 0) !== (kb[i] ?? 0)) return (ka[i] ?? 0) - (kb[i] ?? 0);
      }
      return (b.vertices || 0) - (a.vertices || 0);
    });
  }
  return [...list].sort((a, b) => (b.vertices || 0) - (a.vertices || 0));
}

function materialForAsset(asset) {
  meshColor = asset.category === "vehicles" ? 0xffaa55 : 0x66ccff;
}

function resolvePointSize(extents, vertexCount) {
  if (!extents || !vertexCount) return 1.5;
  const maxDim = Math.max(extents.spanX, extents.spanY, extents.spanZ, 0.01);
  const spacing = maxDim / Math.cbrt(vertexCount);
  // Screen-space points: keep smaller than typical vertex spacing when zoomed in.
  const px = spacing * 120;
  return Math.max(0.8, Math.min(2.5, px));
}

function makePointsMaterial(sizePx = pointSize) {
  return new THREE.PointsMaterial({
    size: sizePx,
    color: meshColor,
    sizeAttenuation: false,
    depthTest: true,
    depthWrite: true,
  });
}

function makeMeshMaterial(mode, { engineNormals = false } = {}) {
  if (mode === "wireframe") {
    return new THREE.MeshBasicMaterial({
      color: meshColor,
      wireframe: true,
      depthTest: true,
      depthWrite: true,
      side: THREE.DoubleSide,
    });
  }
  return new THREE.MeshLambertMaterial({
    color: meshColor,
    flatShading: true,
    depthTest: true,
    depthWrite: true,
    side: THREE.FrontSide,
  });
}

async function loadManifest() {
  const res = await fetch(`${OUT_BASE}manifest.json`);
  const text = await res.text();
  if (!res.ok) {
    throw new Error("manifest.json not found — run: python -m tools.extract");
  }
  if (text.trimStart().startsWith("<")) {
    throw new Error(
      "manifest.json not found — run: python -m tools.extract (then restart npm run dev)"
    );
  }
  return JSON.parse(text);
}

function buildAssetIndexFromManifest(manifest) {
  if (manifest.asset_index) {
    return manifest.asset_index;
  }
  // Fallback before asset_index.json exists
  const assets = [];
  for (const seg of manifest.placement_segments || []) {
    const tier = seg.tier || "minor";
    const category =
      seg.label === "shared_props" || tier === "minor"
        ? "props"
        : tier === "major_geometry" || tier === "medium_geometry"
          ? "track"
          : "other";
    assets.push({
      id: seg.file,
      category,
      name: seg.file,
      path: `scenes/${seg.file}`,
      vertices: seg.vertices,
      ...seg,
    });
  }
  for (const m of manifest.meshes || []) {
    const bank = m.name.replace("_points", "");
    assets.push({
      id: m.name,
      category: "other",
      name: `${m.name} (legacy ROM bank)`,
      path: m.path,
      source: "polygon_rom_bank",
      bank,
      deprecated: true,
    });
  }
  return {
    categories: {
      track: { title: "Track geometry", description: "" },
      vehicles: { title: "Vehicles", description: "" },
      props: { title: "Props", description: "" },
      overview: { title: "Overview", description: "" },
      other: { title: "Other", description: "" },
    },
    assets,
    default_asset_id: assets[0]?.id,
  };
}

function indexAssets(index) {
  assetsByCategory = new Map();
  for (const cat of CATEGORY_ORDER) {
    assetsByCategory.set(cat, []);
  }
  for (const asset of index.assets || []) {
    const cat = asset.category || "other";
    if (!assetsByCategory.has(cat)) {
      assetsByCategory.set(cat, []);
    }
    assetsByCategory.get(cat).push(asset);
  }
  for (const [cat, list] of assetsByCategory.entries()) {
    assetsByCategory.set(cat, sortAssets(list));
  }
}

function updateCameraPlanes() {
  if (!camera || !controls) return;
  const dist = Math.max(controls.getDistance(), 0.001);
  const ref = Math.max(sceneBounds.maxDim, 1);
  camera.near = Math.max(Math.min(dist / 500, dist / 10), 0.001, ref / 200000);
  camera.far = Math.max(dist * 80, ref * 30, camera.near + 1000);
  camera.updateProjectionMatrix();
}

/** Wheel zoom: direct dolly toward orbit target (no zoom-to-cursor drift on large tracks). */
function installConsistentWheelZoom(controls, camera) {
  const el = controls.domElement;
  el.removeEventListener("wheel", controls._onMouseWheel);
  el.addEventListener(
    "wheel",
    (event) => {
      if (!controls.enabled || !controls.enableZoom) return;
      event.preventDefault();

      let deltaY = event.deltaY;
      if (event.deltaMode === 1) deltaY *= 16;
      else if (event.deltaMode === 2) deltaY *= 100;
      // Ignore macOS pinch ctrlKey 10× boost from OrbitControls._customWheelEvent.

      const dist = Math.max(controls.getDistance(), controls.minDistance);
      const normalized = Math.min(Math.abs(deltaY) * 0.012, 2.5);
      const step = Math.pow(0.92, controls.zoomSpeed * normalized);
      const newDist =
        deltaY < 0
          ? Math.max(controls.minDistance, dist / step)
          : Math.min(controls.maxDistance, dist * step);

      const offset = camera.position.clone().sub(controls.target);
      if (offset.lengthSq() < 1e-12) return;
      offset.multiplyScalar(newDist / dist);
      camera.position.copy(controls.target).add(offset);
      controls.update();
    },
    { passive: false },
  );
}

const focusRaycaster = new THREE.Raycaster();
const focusNdc = new THREE.Vector2();

function installFocusOnDoubleClick(controls, camera, viewport) {
  viewport.addEventListener("dblclick", (event) => {
    if (!meshGroup?.children.length) return;
    const rect = renderer.domElement.getBoundingClientRect();
    focusNdc.set(
      ((event.clientX - rect.left) / rect.width) * 2 - 1,
      -((event.clientY - rect.top) / rect.height) * 2 + 1,
    );
    focusRaycaster.setFromCamera(focusNdc, camera);
    const hits = focusRaycaster.intersectObject(meshGroup, true);
    if (!hits.length) return;
    controls.target.copy(hits[0].point);
    controls.update();
  });
}

function initThree() {
  const viewport = document.getElementById("viewport");
  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x1b1b1b);

  camera = new THREE.PerspectiveCamera(55, 1, 0.1, 100000);
  camera.position.set(800, 600, 1200);

  renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setPixelRatio(window.devicePixelRatio);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.sortObjects = true;
  viewport.appendChild(renderer.domElement);

  controls = new OrbitControls(camera, renderer.domElement);
  controls.target.set(0, 0, 0);
  controls.zoomToCursor = false;
  controls.zoomSpeed = 2;
  controls.minDistance = 0.001;
  controls.maxDistance = 500000;
  installConsistentWheelZoom(controls, camera);
  installFocusOnDoubleClick(controls, camera, viewport);
  controls.addEventListener("change", updateCameraPlanes);

  const keyLight = new THREE.DirectionalLight(0xffffff, 1.1);
  keyLight.position.set(1, 2, 1);
  scene.add(keyLight);
  const fillLight = new THREE.DirectionalLight(0xaaccff, 0.35);
  fillLight.position.set(-1.5, 0.5, -1);
  scene.add(fillLight);
  scene.add(new THREE.AmbientLight(0xffffff, 0.45));

  gridHelper = new THREE.GridHelper(4000, 40, 0x444444, 0x333333);
  scene.add(gridHelper);

  axesHelper = new THREE.AxesHelper(1);
  scene.add(axesHelper);

  meshGroup = new THREE.Group();
  scene.add(meshGroup);

  heightmapMesh = null;

  function resize() {
    const w = viewport.clientWidth;
    const h = viewport.clientHeight;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
  }
  window.addEventListener("resize", resize);
  resize();

  function animate() {
    requestAnimationFrame(animate);
    controls.update();
    renderer.render(scene, camera);
  }
  animate();
}

function setupClipSliders(yMin, yMax, zMin, zMax) {
  const yPad = Math.max(20, (yMax - yMin) * 0.05);
  const zPad = Math.max(20, (zMax - zMin) * 0.05);
  const yLo = Math.floor(yMin - yPad);
  const yHi = Math.ceil(yMax + yPad);
  const zLo = Math.floor(zMin - zPad);
  const zHi = Math.ceil(zMax + zPad);
  meshYBounds = { min: yLo, max: yHi };
  meshZBounds = { min: zLo, max: zHi };
  for (const [id, lo, hi, val] of [
    ["y-min", yLo, yHi, yLo],
    ["y-max", yLo, yHi, yHi],
    ["z-min", zLo, zHi, zLo],
    ["z-max", zLo, zHi, zHi],
  ]) {
    const el = document.getElementById(id);
    el.min = String(lo);
    el.max = String(hi);
    el.step = String(Math.max(0.01, (hi - lo) / 200));
    el.value = String(val);
  }
  updateClipInfo();
}

function computeExtents(positions) {
  if (!positions.length) return null;
  let xMin = Infinity;
  let yMin = Infinity;
  let zMin = Infinity;
  let xMax = -Infinity;
  let yMax = -Infinity;
  let zMax = -Infinity;
  for (let i = 0; i < positions.length; i += 3) {
    const x = positions[i];
    const y = positions[i + 1];
    const z = positions[i + 2];
    xMin = Math.min(xMin, x);
    yMin = Math.min(yMin, y);
    zMin = Math.min(zMin, z);
    xMax = Math.max(xMax, x);
    yMax = Math.max(yMax, y);
    zMax = Math.max(zMax, z);
  }
  const sx = xMax - xMin;
  const sy = yMax - yMin;
  const sz = zMax - zMin;
  const axes = [
    { name: "X", span: sx },
    { name: "Y", span: sy },
    { name: "Z", span: sz },
  ].sort((a, b) => b.span - a.span);
  return {
    x: [xMin, xMax],
    y: [yMin, yMax],
    z: [zMin, zMax],
    spanX: sx,
    spanY: sy,
    spanZ: sz,
    longestAxis: axes[0].name,
    thinnestAxis: axes[2].name,
  };
}

function formatExtents(ext) {
  if (!ext) return "";
  const thin =
    ext.thinnestAxis === "Y"
      ? " · low Y = looks flat from the side"
      : ` · thinnest axis: ${ext.thinnestAxis}`;
  return `Extents X×Y×Z = ${ext.spanX.toFixed(2)} × ${ext.spanY.toFixed(2)} × ${ext.spanZ.toFixed(2)} · length mostly ${ext.longestAxis}${thin}`;
}

function readClipBounds() {
  const yLo = parseFloat(document.getElementById("y-min").value);
  const yHi = parseFloat(document.getElementById("y-max").value);
  const zLo = parseFloat(document.getElementById("z-min").value);
  const zHi = parseFloat(document.getElementById("z-max").value);
  return {
    yLo: Math.min(yLo, yHi),
    yHi: Math.max(yLo, yHi),
    zLo: Math.min(zLo, zHi),
    zHi: Math.max(zLo, zHi),
  };
}

function updateClipInfo() {
  const { yLo, yHi, zLo, zHi } = readClipBounds();
  document.getElementById("clip-range-info").textContent =
    `Clip Y: ${yLo.toFixed(2)} … ${yHi.toFixed(2)} · Z: ${zLo.toFixed(2)} … ${zHi.toFixed(2)}`;
}

function filterGeometry(positions, faces, faceNormals, clip) {
  const vertexCount = positions.length / 3;
  const oldToNew = new Int32Array(vertexCount).fill(-1);
  const filtered = [];
  for (let i = 0; i < vertexCount; i += 1) {
    const x = positions[i * 3];
    const y = positions[i * 3 + 1];
    const z = positions[i * 3 + 2];
    if (y >= clip.yLo && y <= clip.yHi && z >= clip.zLo && z <= clip.zHi) {
      oldToNew[i] = filtered.length / 3;
      filtered.push(x, y, z);
    }
  }

  const filteredFaces = [];
  const filteredFaceNormals = [];
  for (let fi = 0; fi < faces.length; fi += 1) {
    const face = faces[fi];
    const mapped = face.map((idx) => oldToNew[idx]);
    if (!mapped.every((idx) => idx >= 0)) continue;
    if (mapped.length === 4) {
      filteredFaces.push([mapped[0], mapped[1], mapped[2]]);
      filteredFaceNormals.push(faceNormals?.[fi] ?? null);
      filteredFaces.push([mapped[0], mapped[2], mapped[3]]);
      filteredFaceNormals.push(faceNormals?.[fi] ?? null);
    } else if (mapped.length >= 3) {
      filteredFaces.push(mapped.slice(0, 3));
      filteredFaceNormals.push(faceNormals?.[fi] ?? null);
    }
  }
  return { positions: filtered, faces: filteredFaces, faceNormals: filteredFaceNormals };
}

function samplePositions(positions, maxPoints) {
  const count = positions.length / 3;
  if (count <= maxPoints) return positions;
  const stride = Math.ceil(count / maxPoints);
  const sampled = [];
  for (let i = 0; i < positions.length; i += 3 * stride) {
    sampled.push(positions[i], positions[i + 1], positions[i + 2]);
  }
  return sampled;
}

function vtx(positions, i) {
  return [positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2]];
}

function dist3(a, b) {
  const dx = a[0] - b[0];
  const dy = a[1] - b[1];
  const dz = a[2] - b[2];
  return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

function triangleArea(positions, a, b, c) {
  const va = vtx(positions, a);
  const vb = vtx(positions, b);
  const vc = vtx(positions, c);
  const ab = [vb[0] - va[0], vb[1] - va[1], vb[2] - va[2]];
  const ac = [vc[0] - va[0], vc[1] - va[1], vc[2] - va[2]];
  const cx = ab[1] * ac[2] - ab[2] * ac[1];
  const cy = ab[2] * ac[0] - ab[0] * ac[2];
  const cz = ab[0] * ac[1] - ab[1] * ac[0];
  return 0.5 * Math.sqrt(cx * cx + cy * cy + cz * cz);
}

function triangulateFace(face) {
  if (face.length === 4) {
    return [
      [face[0], face[1], face[2]],
      [face[0], face[2], face[3]],
    ];
  }
  if (face.length >= 3) return [face.slice(0, 3)];
  return [];
}

function normalizeNormal(n) {
  if (!n) return null;
  const len = Math.sqrt(n[0] * n[0] + n[1] * n[1] + n[2] * n[2]);
  if (len < 1e-6) return null;
  return [n[0] / len, n[1] / len, n[2] / len];
}

function triangleNormalFromPositions(positions, a, b, c) {
  const va = vtx(positions, a);
  const vb = vtx(positions, b);
  const vc = vtx(positions, c);
  const ab = [vb[0] - va[0], vb[1] - va[1], vb[2] - va[2]];
  const ac = [vc[0] - va[0], vc[1] - va[1], vc[2] - va[2]];
  const nx = ab[1] * ac[2] - ab[2] * ac[1];
  const ny = ab[2] * ac[0] - ab[0] * ac[2];
  const nz = ab[0] * ac[1] - ab[1] * ac[0];
  const len = Math.sqrt(nx * nx + ny * ny + nz * nz);
  if (len < 1e-12) return null;
  return [nx / len, ny / len, nz / len];
}

function buildMeshIndices(positions, faces, { solid = false, faceNormals = null } = {}) {
  const indices = [];
  let dropped = 0;
  const vertCount = positions.length / 3;
  const normalArray = faceNormals?.length ? new Float32Array(positions.length) : null;
  for (let fi = 0; fi < faces.length; fi += 1) {
    const face = faces[fi];
    for (const [a, b, c] of triangulateFace(face)) {
      if (a < 0 || b < 0 || c < 0 || a >= vertCount || b >= vertCount || c >= vertCount) {
        dropped += 1;
        continue;
      }
      if (a === b || b === c || a === c) {
        dropped += 1;
        continue;
      }
      const area = triangleArea(positions, a, b, c);
      if (area < 1e-5) {
        dropped += 1;
        continue;
      }
      if (solid) {
        const va = vtx(positions, a);
        const vb = vtx(positions, b);
        const vc = vtx(positions, c);
        const edges = [dist3(va, vb), dist3(vb, vc), dist3(va, vc)];
        const emin = Math.min(...edges);
        const emax = Math.max(...edges);
        if (emin / emax < 0.025) {
          dropped += 1;
          continue;
        }
      }
      indices.push(a, b, c);
      const n =
        normalizeNormal(faceNormals?.[fi]) ??
        triangleNormalFromPositions(positions, a, b, c);
      if (normalArray && n) {
        for (const idx of [a, b, c]) {
          normalArray[idx * 3] = n[0];
          normalArray[idx * 3 + 1] = n[1];
          normalArray[idx * 3 + 2] = n[2];
        }
      }
    }
  }
  return { indices, dropped, normalArray };
}

function expandPointCloud(positions, faces) {
  const out = [];
  for (const face of faces) {
    for (const idx of face) {
      if (idx < 0 || idx * 3 + 2 >= positions.length) continue;
      out.push(positions[idx * 3], positions[idx * 3 + 1], positions[idx * 3 + 2]);
    }
  }
  return out;
}

function filterPointCloud(positions, clip) {
  const filtered = [];
  for (let i = 0; i < positions.length; i += 3) {
    const y = positions[i + 1];
    const z = positions[i + 2];
    if (y >= clip.yLo && y <= clip.yHi && z >= clip.zLo && z <= clip.zHi) {
      filtered.push(positions[i], positions[i + 1], positions[i + 2]);
    }
  }
  return filtered;
}

function rebuildMeshDisplay() {
  meshGroup.clear();
  const clip = readClipBounds();
  updateClipInfo();

  const filteredFaceNormals = meshFaceNormalIndicesAll.map((idx) =>
    idx === null || idx === undefined ? null : meshNormalsAll[idx],
  );
  const { positions, faces, faceNormals } = filterGeometry(
    meshPositionsAll,
    meshFacesAll,
    filteredFaceNormals,
    clip,
  );
  const total = meshPositionsAll.length / 3;
  const inBand = positions.length / 3;
  meshExtents = computeExtents(meshPositionsAll);
  const info = document.getElementById("mesh-info");
  const extentLine = formatExtents(meshExtents);
  const mode = displayMode;
  const hasFaces = meshFacesAll.length > 0;

  let effectiveMode = mode;
  if (mode !== "points" && !hasFaces) {
    effectiveMode = "points";
    document.getElementById("display-mode").value = "points";
  }

  const texturedLike =
    effectiveMode === "textured" || effectiveMode === "uv-atlas";
  if (texturedLike && !texturedMeshObject) {
    info.textContent =
      "No textured export for this asset — use wireframe/solid or pick a course track.";
    if (currentAsset) showAssetDetail(currentAsset);
    return;
  }

  if (texturedLike && texturedMeshObject) {
    meshGroup.add(texturedMeshObject);
    const texFaces = currentAsset?.textured_faces;
    const variants =
      currentAsset?.textured_palette_variants || countTexturedMaterials(texturedMeshObject);
    const countLine = texFaces
      ? `${texFaces.toLocaleString()} textured faces`
      : "Textured mesh";
    const cutout = texturedMeshObject?.userData?.cutoutMaterials;
    const cutoutLine = cutout ? ` · ${cutout} cutout mats` : "";
    const variantLine =
      effectiveMode === "uv-atlas"
        ? " · 2 atlas sheets (cb0)"
        : variants
          ? ` · ${variants} palette sheets`
          : "";
    const phaseLine =
      effectiveMode === "uv-atlas"
        ? "phase 2a: UV mapping only"
        : "phase 2b: per-material palette";
    info.textContent = extentLine
      ? `${countLine}${variantLine}${cutoutLine} · ${phaseLine}\n${extentLine}`
      : `${countLine}${variantLine}${cutoutLine} · ${phaseLine}`;
    if (currentAsset) showAssetDetail(currentAsset);
    return;
  }

  if (effectiveMode === "points") {
    const maxPoints = 120000;
    const stripTotal = meshPositionsAll.length / 3;
    let pointSource;
    let pointLabel;
    if (meshFacesAll.length > 0) {
      pointSource = expandPointCloud(meshPositionsAll, meshFacesAll);
      pointLabel = `${pointSource.length / 3 | 0} face-corner pts · ${stripTotal | 0} strip verts`;
    } else {
      pointSource = meshPositionsAll;
      pointLabel = `${stripTotal | 0} strip verts`;
    }
    const clipped = filterPointCloud(pointSource, clip);
    const sampled = samplePositions(clipped, maxPoints);
    const px = resolvePointSize(meshExtents, clipped.length / 3);
    pointSize = px;
    if (sampled.length) {
      const geom = new THREE.BufferGeometry();
      geom.setAttribute("position", new THREE.Float32BufferAttribute(sampled, 3));
      meshGroup.add(new THREE.Points(geom, makePointsMaterial(px)));
    }
    const shown = sampled.length / 3;
    const inBand = clipped.length / 3;
    const countLine =
      shown < inBand
        ? `${shown | 0} points shown · ${inBand | 0} in clip · ${pointLabel}`
        : `${inBand | 0} points · ${pointLabel}`;
    info.textContent = extentLine ? `${countLine}\n${extentLine}` : countLine;
  } else if (positions.length && faces.length) {
    const geom = new THREE.BufferGeometry();
    geom.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    const { indices, dropped, normalArray } = buildMeshIndices(positions, faces, {
      solid: effectiveMode === "solid",
      faceNormals,
    });
    geom.setIndex(indices);
    const engineNormals = normalArray !== null;
    if (engineNormals) {
      geom.setAttribute("normal", new THREE.BufferAttribute(normalArray, 3));
    } else {
      geom.computeVertexNormals();
    }
    meshGroup.add(
      new THREE.Mesh(geom, makeMeshMaterial(effectiveMode, { engineNormals })),
    );
    const normalLine = engineNormals ? " · MAME face normals" : "";
    const dropLine = dropped ? ` · ${dropped | 0} degenerate tris culled` : "";
    info.textContent = `${indices.length / 3 | 0} tris · ${inBand | 0} verts in clip · ${total | 0} total · ${meshFacesAll.length | 0} source faces${dropLine}${normalLine}\n${extentLine}`;
  } else {
    info.textContent = `${inBand | 0} / ${total | 0} vertices · clip removed all faces\n${extentLine}`;
  }

  if (currentAsset) showAssetDetail(currentAsset);
}

function parseObjVertices(text, faceOffset = 0, normalOffset = 0) {
  const positions = [];
  const normals = [];
  const faces = [];
  const faceNormalIndices = [];
  const ys = [];
  const zs = [];
  for (const line of text.split("\n")) {
    if (line.startsWith("v ")) {
      const [, x, y, z] = line.split(/\s+/);
      positions.push(parseFloat(x), parseFloat(y), parseFloat(z));
      ys.push(parseFloat(y));
      zs.push(parseFloat(z));
    } else if (line.startsWith("vn ")) {
      const [, nx, ny, nz] = line.split(/\s+/);
      normals.push([parseFloat(nx), parseFloat(ny), parseFloat(nz)]);
    } else if (line.startsWith("f ") && faceOffset >= 0) {
      const vertParts = [];
      const normalParts = [];
      for (const token of line.trim().split(/\s+/).slice(1)) {
        const chunks = token.split("/");
        vertParts.push(parseInt(chunks[0], 10) - 1 + faceOffset);
        if (chunks.length >= 3 && chunks[2]) {
          normalParts.push(parseInt(chunks[2], 10) - 1 + normalOffset);
        }
      }
      if (vertParts.length >= 3) {
        faces.push(vertParts);
        faceNormalIndices.push(
          normalParts.length ? normalParts[0] : null,
        );
      }
    }
  }
  return { positions, normals, faces, faceNormalIndices, ys, zs };
}

function configureTextureMap(map) {
  if (!map) return;
  // Raw palette texels — avoid MeshBasicMaterial color-space/tone-map transforms.
  map.colorSpace = THREE.NoColorSpace;
  map.flipY = true;
  map.wrapS = THREE.ClampToEdgeWrapping;
  map.wrapT = THREE.ClampToEdgeWrapping;
  map.generateMipmaps = false;
  map.magFilter = THREE.NearestFilter;
  map.minFilter = THREE.NearestFilter;
  map.needsUpdate = true;
}

function textureMapReady(map) {
  return Boolean(map?.image && map.image.width > 0 && map.image.height > 0);
}

function materialHasTexture(mat) {
  if (!mat) return false;
  if (mat instanceof THREE.ShaderMaterial) return textureMapReady(mat.uniforms?.map?.value);
  return textureMapReady(mat.map);
}

function disposeObject3D(object) {
  if (!object) return;
  const geometries = new Set();
  const materials = new Set();
  object.traverse((child) => {
    if (child.geometry) geometries.add(child.geometry);
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    for (const mat of mats) {
      if (mat) materials.add(mat);
    }
  });
  for (const geometry of geometries) geometry.dispose();
  for (const material of materials) material.dispose?.();
}

function toUnlitTexturedMaterial(material) {
  if (material instanceof THREE.ShaderMaterial && material.uniforms?.map?.value) {
    return material;
  }
  if (material instanceof THREE.MeshBasicMaterial && textureMapReady(material.map)) {
    return material;
  }
  if (textureMapReady(material?.map)) {
    const name = material.name || "";
    const cutout = Boolean(material.userData?.cutout || name.endsWith("_tr"));
    configureTextureMap(material.map);
    return buildPaletteMaterial(name, material.map);
  }
  if (material?.color) {
    return new THREE.MeshBasicMaterial({
      name: material.name,
      color: material.color,
      side: THREE.FrontSide,
      depthTest: true,
      depthWrite: true,
      transparent: material.transparent,
      opacity: material.opacity ?? 1,
    });
  }
  return material;
}

function usesGenericIndexSheets(object) {
  let generic = false;
  object?.traverse((child) => {
    if (!child.isMesh || generic) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    for (const mat of mats) {
      const name = (mat?.name || "").toLowerCase();
      if (name === "sheet0" || name === "sheet1") {
        generic = true;
        break;
      }
    }
  });
  return generic;
}

async function applyUvAtlasMaterials(object) {
  const sheet0Path =
    manifestTextures.find((t) => t.name === "sheet0_logical_2048x1024_palette_cb0")?.path ||
    "textures/sheet0_logical_2048x1024_palette_cb0.png";
  const sheet1Path =
    manifestTextures.find((t) => t.name === "sheet1_logical_2048x1024_palette_cb0")?.path ||
    "textures/sheet1_logical_2048x1024_palette_cb0.png";
  const loader = new THREE.TextureLoader();
  const maps = {};
  if (sheet0Path) {
    maps.sheet0 = await loader.loadAsync(`${OUT_BASE}${sheet0Path}`);
    configureTextureMap(maps.sheet0);
  }
  if (sheet1Path) {
    maps.sheet1 = await loader.loadAsync(`${OUT_BASE}${sheet1Path}`);
    configureTextureMap(maps.sheet1);
  }
  const materialCache = {};
  function sheetMaterial(prefix) {
    if (materialCache[prefix]) return materialCache[prefix];
    const map = maps[prefix];
    if (!map) return null;
    materialCache[prefix] = buildPaletteMaterial(`uv_atlas_${prefix}`, map);
    return materialCache[prefix];
  }
  object.traverse((child) => {
    if (!child.isMesh) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    const remapped = mats.map((mat) => {
      const name = mat?.name || "";
      if (name.startsWith("s1_")) return sheetMaterial("sheet1") || mat;
      if (name.startsWith("s0_")) return sheetMaterial("sheet0") || mat;
      return mat;
    });
    child.material = Array.isArray(child.material) ? remapped : remapped[0];
  });
  object.userData.displayTextureMode = "uv-atlas";
  return prepareTexturedObject(object);
}

async function applyTexturedDisplayMode(object, asset, mode) {
  if (!object || !asset) return object;
  if (mode === "uv-atlas") {
    return applyUvAtlasMaterials(object);
  }
  if (mode === "textured") {
    await rebindPaletteTextures(object, asset.course_id, object.userData?.mtlMaterials);
    object.userData.displayTextureMode = "textured";
    return prepareTexturedObject(object);
  }
  return object;
}

async function applyIndexSheetMaterials(object) {
  const sheet0Path = manifestTextures.find((t) => t.name === "sheet0_logical_2048x1024")?.path;
  const sheet1Path = manifestTextures.find((t) => t.name === "sheet1_logical_2048x1024")?.path;
  if (!sheet0Path && !sheet1Path) return object;
  const loader = new THREE.TextureLoader();
  const maps = {};
  if (sheet0Path) {
    maps.sheet0 = await loader.loadAsync(`${OUT_BASE}${sheet0Path}`);
    configureTextureMap(maps.sheet0);
  }
  if (sheet1Path) {
    maps.sheet1 = await loader.loadAsync(`${OUT_BASE}${sheet1Path}`);
    configureTextureMap(maps.sheet1);
  }
  object.traverse((child) => {
    if (!child.isMesh) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    const remapped = mats.map((mat) => {
      const name = (mat?.name || "").toLowerCase();
      if (name !== "sheet0" && name !== "sheet1") {
        return toUnlitTexturedMaterial(mat);
      }
      const map = name === "sheet1" ? maps.sheet1 || maps.sheet0 : maps.sheet0;
      if (!map) return toUnlitTexturedMaterial(mat);
      return new THREE.MeshBasicMaterial({ map, side: THREE.FrontSide });
    });
    child.material = Array.isArray(child.material) ? remapped : remapped[0];
  });
  return object;
}

async function prepareTexturedObject(object) {
  if (usesGenericIndexSheets(object)) {
    await applyIndexSheetMaterials(object);
  }
  let missingMaps = 0;
  let cutoutMats = 0;
  object.traverse((child) => {
    if (!child.isMesh) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    const unlit = mats.map((mat) => {
      if ((mat?.name || "").endsWith("_tr")) {
        cutoutMats += 1;
      }
      if (!materialHasTexture(mat) && mat?.name && !mat?.color) missingMaps += 1;
      if (
        (mat instanceof THREE.ShaderMaterial && materialHasTexture(mat)) ||
        (mat instanceof THREE.MeshBasicMaterial && textureMapReady(mat.map))
      ) {
        return mat;
      }
      return toUnlitTexturedMaterial(mat);
    });
    child.material = Array.isArray(child.material) ? unlit : unlit[0];
    if (unlit.some((mat) => mat.transparent)) {
      child.renderOrder = 1;
    }
  });
  if (cutoutMats > 0) {
    object.userData.cutoutMaterials = cutoutMats;
  }
  if (missingMaps > 0) {
    console.warn(
      `Textured mesh: ${missingMaps} material(s) have no map_Kd — check MTL paths or re-run scenes extract`
    );
  }
  return object;
}

function countTexturedMaterials(object) {
  const names = new Set();
  object?.traverse((child) => {
    if (!child.isMesh) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    for (const mat of mats) {
      if (mat?.name) names.add(mat.name);
    }
  });
  return names.size;
}

async function loadObjFile(baseUrl, file) {
  const { OBJLoader } = await import("three/examples/jsm/loaders/OBJLoader.js");
  const objLoader = new OBJLoader();
  objLoader.setPath(baseUrl);
  return new Promise((resolve, reject) => {
    objLoader.load(file, resolve, undefined, reject);
  });
}

async function applyFallbackTextures(object) {
  const sheet0Path =
    manifestTextures.find((t) => t.name.includes("palette_cb0") && t.name.startsWith("sheet0"))?.path ||
    manifestTextures.find((t) => t.name === "sheet0_logical_2048x1024")?.path;
  const sheet1Path =
    manifestTextures.find((t) => t.name.includes("palette_cb0") && t.name.startsWith("sheet1"))?.path ||
    manifestTextures.find((t) => t.name === "sheet1_logical_2048x1024")?.path;
  const loader = new THREE.TextureLoader();
  const maps = {};
  if (sheet0Path) {
    maps.sheet0 = await loader.loadAsync(`${OUT_BASE}${sheet0Path}`);
    maps.sheet0.colorSpace = THREE.SRGBColorSpace;
    maps.sheet0.flipY = true;
  }
  if (sheet1Path) {
    maps.sheet1 = await loader.loadAsync(`${OUT_BASE}${sheet1Path}`);
    maps.sheet1.colorSpace = THREE.SRGBColorSpace;
    maps.sheet1.flipY = true;
  }
  object.traverse((child) => {
    if (!child.isMesh) return;
    const groupName = (child.name || "").toLowerCase();
    const map =
      groupName.includes("sheet1") || groupName.includes("sheet_1")
        ? maps.sheet1 || maps.sheet0
        : maps.sheet0;
    if (!map) return;
    child.material = new THREE.MeshBasicMaterial({ map, side: THREE.FrontSide });
  });
}

async function rebindPaletteTextures(object, courseId, mtlMaterials = null) {
  if (!courseId || !object) return object;
  const { TextureLoader } = await import("three");
  const loader = new TextureLoader();
  const textureCache = new Map();
  const texturePending = new Map();
  const materialCache = new Map();

  async function loadPaletteTexture(name) {
    const url = paletteTextureUrl(courseId, name);
    if (textureCache.has(url)) return textureCache.get(url);
    if (texturePending.has(url)) return texturePending.get(url);
    const cutout = name.endsWith("_tr");
    const pending = loader
      .loadAsync(url)
      .then((tex) => {
        configureTextureMap(tex);
        textureCache.set(url, tex);
        texturePending.delete(url);
        return tex;
      })
      .catch((err) => {
        texturePending.delete(url);
        throw err;
      });
    texturePending.set(url, pending);
    return pending;
  }

  function cachedSolidMaterial(name) {
    if (materialCache.has(name)) return materialCache.get(name);
    const kd = mtlMaterials?.materialsInfo?.[name]?.kd;
    if (!kd) return null;
    const mat = new THREE.MeshBasicMaterial({
      name,
      color: new THREE.Color(kd[0], kd[1], kd[2]),
      side: THREE.DoubleSide,
      depthTest: true,
      depthWrite: true,
    });
    materialCache.set(name, mat);
    return mat;
  }

  const paletteNames = new Set();
  object.traverse((child) => {
    if (!child.isMesh) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    for (const mat of mats) {
      const name = mat?.name || "";
      if (name.startsWith("s0_cb") || name.startsWith("s1_cb")) paletteNames.add(name);
    }
  });

  await Promise.all(
    [...paletteNames].map(async (name) => {
      try {
        const map = await loadPaletteTexture(name);
        if (!materialCache.has(name)) {
          materialCache.set(name, buildPaletteMaterial(name, map));
        }
      } catch (err) {
        console.error(`Palette texture failed: ${paletteTextureUrl(courseId, name)}`, err);
      }
    })
  );

  object.traverse((child) => {
    if (!child.isMesh) return;
    const oldMats = Array.isArray(child.material) ? child.material : [child.material];
    const newMats = oldMats.map((mat) => {
      const name = mat?.name || "";
      if (name.startsWith("s0_cb") || name.startsWith("s1_cb")) {
        return materialCache.get(name) || mat;
      }
      return cachedSolidMaterial(name) || mat;
    });
    child.material = Array.isArray(child.material) ? newMats : newMats[0];
  });
  return object;
}

async function loadTexturedObj(relPath, courseId) {
  const { MTLLoader } = await import("three/examples/jsm/loaders/MTLLoader.js");
  const { LoadingManager } = await import("three");
  const slash = relPath.lastIndexOf("/");
  const dir = slash >= 0 ? relPath.slice(0, slash + 1) : "";
  const file = slash >= 0 ? relPath.slice(slash + 1) : relPath;
  const mtlFile = file.replace(/\.obj$/i, ".mtl");
  const baseUrl = `${OUT_BASE}${dir}`;

  try {
    const materials = await new Promise((resolve, reject) => {
      let parsed = null;
      const manager = new LoadingManager(
        () => resolve(parsed),
        undefined,
        reject
      );
      const mtlLoader = new MTLLoader(manager);
      // map_Kd paths are absolute from site root (/textures/palette_cache/...).
      mtlLoader.setResourcePath(OUT_BASE);
      mtlLoader.setPath(`${OUT_BASE}${dir}`);
      mtlLoader.load(
        mtlFile,
        (loaded) => {
          parsed = loaded;
          stripMtlTexturePaths(loaded.materialsInfo);
          loaded.preload();
          for (const matName of Object.keys(loaded.materialsInfo || {})) {
            if (!matName.endsWith("_tr")) continue;
            const mat = loaded.materials[matName];
            if (mat) mat.userData.cutout = true;
          }
        },
        undefined,
        reject
      );
    });
    const { OBJLoader } = await import("three/examples/jsm/loaders/OBJLoader.js");
    const objLoader = new OBJLoader();
    objLoader.setMaterials(materials);
    objLoader.setPath(baseUrl);
    const object = await new Promise((resolve, reject) => {
      objLoader.load(file, resolve, undefined, reject);
    });
    object.userData.courseId = courseId;
    object.userData.mtlMaterials = materials;
    splitMultiMaterialMeshes(object);
    return object;
  } catch (err) {
    console.warn("MTL load failed, using manifest texture fallback:", err);
    const object = await loadObjFile(baseUrl, file);
    object.userData.courseId = courseId;
    splitMultiMaterialMeshes(object);
    return object;
  }
}

function updateDisplayModeOptions(asset) {
  const select = document.getElementById("display-mode");
  const hasTextured = Boolean(asset?.textured_path);
  for (const value of ["uv-atlas", "textured"]) {
    const opt = [...select.options].find((o) => o.value === value);
    if (!opt) continue;
    opt.disabled = !hasTextured;
    if (value === "uv-atlas") {
      opt.label = hasTextured
        ? "UV atlas (phase 2a — mapping only)"
        : "UV atlas (not available)";
    } else {
      opt.label = hasTextured
        ? "Textured (phase 2b — per-material palette)"
        : "Textured (not available)";
    }
  }
}

function preferredDisplayMode(asset) {
  if (asset?.textured_path) return "textured";
  if (asset?.faces > 0 && asset.category === "track") return "wireframe";
  if (asset?.faces > 0 && asset.category === "vehicles" && asset.role === "body_shell") {
    return "wireframe";
  }
  return displayMode === "textured" ? "points" : displayMode;
}

async function loadMesh(asset) {
  currentAsset = asset;
  materialForAsset(asset);
  showAssetDetail(asset);
  const paths = [asset.path, ...(asset.viewer_includes || [])];
  meshPositionsAll = [];
  meshFacesAll = [];
  meshNormalsAll = [];
  meshFaceNormalIndicesAll = [];
  if (texturedMeshObject) {
    disposeObject3D(texturedMeshObject);
  }
  texturedMeshObject = null;
  const ys = [];
  const zs = [];
  updateDisplayModeOptions(asset);
  displayMode = preferredDisplayMode(asset);
  document.getElementById("display-mode").value = displayMode;
  if (asset.textured_path) {
    try {
      texturedMeshObject = await loadTexturedObj(asset.textured_path, asset.course_id);
      if (displayMode === "textured" || displayMode === "uv-atlas") {
        await applyTexturedDisplayMode(texturedMeshObject, asset, displayMode);
      }
    } catch (err) {
      console.warn("Textured mesh load failed:", err);
    }
  }
  for (const rel of paths) {
    const text = await (await fetch(`${OUT_BASE}${rel}`)).text();
    const chunk = parseObjVertices(
      text,
      meshPositionsAll.length / 3,
      meshNormalsAll.length,
    );
    meshPositionsAll.push(...chunk.positions);
    meshNormalsAll.push(...chunk.normals);
    meshFacesAll.push(...chunk.faces);
    meshFaceNormalIndicesAll.push(...chunk.faceNormalIndices);
    ys.push(...chunk.ys);
    zs.push(...chunk.zs);
  }
  if (!ys.length) {
    meshGroup.clear();
    document.getElementById("mesh-info").textContent = "No vertices in file";
    return;
  }
  ys.sort((a, b) => a - b);
  zs.sort((a, b) => a - b);
  setupClipSliders(ys[0], ys[ys.length - 1], zs[0], zs[zs.length - 1]);
  if (asset.textured_path && asset.course_id) {
    const sample = `${OUT_BASE}textures/palette_cache/${asset.course_id}/s0_cb004_lb0000.png`;
    showTextureUrl(sample, `palette sample (${asset.course_id})`);
  } else if (asset.textured_path) {
    const paletteSheet =
      manifestTextures.find((t) => t.name.includes("palette_cb0") && t.name.startsWith("sheet0")) ||
      manifestTextures.find((t) => t.name === "sheet0_logical_2048x1024");
    if (paletteSheet) showTexture(paletteSheet.path);
  }
  rebuildMeshDisplay();
  if (meshGroup.children.length) frameObject(meshGroup);
}

function showAssetDetail(asset) {
  const dl = document.getElementById("asset-detail");
  if (!asset) {
    dl.innerHTML = "";
    return;
  }
  const rows = [];
  const add = (label, value) => {
    if (value !== undefined && value !== null && value !== "") {
      rows.push(`<dt>${label}</dt><dd>${value}</dd>`);
    }
  };
  add("Source", asset.source);
  add("Role", asset.role);
  add("Catalog", asset.catalog_index);
  add("Body catalog", asset.body_catalog_index);
  add("Draw table", asset.draw_table);
  add("Vertices", asset.vertices?.toLocaleString());
  add("Point cloud", asset.point_vertices?.toLocaleString());
  add("Faces", asset.faces?.toLocaleString());
  if (asset.textured_path) {
    add("Textured", asset.textured_path.split("/").pop());
    add("Textured faces", asset.textured_faces?.toLocaleString());
    add("Palette variants", asset.textured_palette_variants?.toLocaleString());
  }
  if (asset.viewer_vertices && asset.viewer_vertices !== asset.vertices) {
    add("Viewer vertices", asset.viewer_vertices.toLocaleString());
  }
  if (asset.viewer_faces && asset.viewer_faces !== asset.faces) {
    add("Viewer faces", asset.viewer_faces.toLocaleString());
  }
  if (asset.viewer_includes?.length) {
    add("Viewer merges", asset.viewer_includes.map((p) => p.split("/").pop()).join(", "));
  }
  if (asset.placement_range) {
    add("Placements", `${asset.placement_range[0]}–${asset.placement_range[1]}`);
  }
  add("Draw layer", asset.draw_layer_index);
  add("Tier", asset.tier);
  add("Phase", asset.phase);
  add("Bank", asset.bank);
  if (asset.rom_offset !== undefined) {
    add("ROM offset", `0x${Number(asset.rom_offset).toString(16)}`);
  }
  add("Span", asset.span);
  add("Geometry id", asset.geometry_id);
  if (asset.geometry_canonical_catalog !== undefined && asset.geometry_canonical_catalog !== asset.catalog_index) {
    add("Same mesh as", `catalog ${asset.geometry_canonical_catalog}`);
  }
  add("Geometry note", asset.geometry_note);
  add("Transforms", asset.transform_source);
  add("Course", asset.course_id);
  add("Parent course", asset.parent_course);
  add("Track object", asset.track_object);
  add("Confidence", asset.confidence);
  if (asset.excluded_placement_ranges?.length) {
    add(
      "Excluded ranges",
      asset.excluded_placement_ranges
        .map((r) => `${r[0]}–${r[1]}`)
        .join(", "),
    );
  }
  if (asset.excluded_placements?.length) {
    add(
      "Excluded placements",
      asset.excluded_placements
        .map((e) => `pl ${e.placement_index} (${e.role})`)
        .join(", "),
    );
  }
  add("Note", asset.note);
  if (asset.deprecated) {
    add("Status", "deprecated");
  }
  if (asset.merged_from?.length) {
    add("Merged segments", asset.merged_from.join(", "));
  }
  if (meshExtents) {
    add("Extents", `X ${meshExtents.spanX.toFixed(2)} · Y ${meshExtents.spanY.toFixed(2)} · Z ${meshExtents.spanZ.toFixed(2)}`);
    add("Longest axis", meshExtents.longestAxis);
  }
  if (asset.bounds) {
    const fmt = (axis) => {
      const b = asset.bounds[axis];
      return b ? `${b[0].toFixed(1)} … ${b[1].toFixed(1)}` : "";
    };
    add("Bounds X", fmt("x"));
    add("Bounds Y", fmt("y"));
    add("Bounds Z", fmt("z"));
  }
  dl.innerHTML = rows.join("");
}

function frameObject(object) {
  const box = new THREE.Box3().setFromObject(object);
  if (box.isEmpty()) return;
  const center = box.getCenter(new THREE.Vector3());
  const size = box.getSize(new THREE.Vector3());
  const maxDim = Math.max(size.x, size.y, size.z, 0.001);
  sceneBounds.maxDim = maxDim;
  controls.target.copy(center);
  // Three.js Y-up: grid is XZ. Elevated 3/4 view so thin-Y vehicles are not edge-on.
  const elev = Math.max(size.y * 1.8, maxDim * 0.75);
  camera.position.copy(center).add(new THREE.Vector3(maxDim * 1.05, elev, maxDim * 1.05));
  controls.minDistance = 0.001;
  controls.maxDistance = maxDim * 50;
  controls.update();
  updateCameraPlanes();
  if (axesHelper) {
    axesHelper.position.copy(center);
    axesHelper.scale.setScalar(maxDim * 0.35);
  }
}

async function loadHeightmap(relativePath) {
  if (heightmapMesh) {
    scene.remove(heightmapMesh);
    heightmapMesh.geometry.dispose();
    heightmapMesh.material.dispose();
    heightmapMesh = null;
  }
  const tex = await new THREE.TextureLoader().loadAsync(`${OUT_BASE}${relativePath}`);
  tex.colorSpace = THREE.SRGBColorSpace;
  const w = tex.image.width;
  const h = tex.image.height;
  const geom = new THREE.PlaneGeometry(w, h, 1, 1);
  geom.rotateX(-Math.PI / 2);
  const mat = new THREE.MeshBasicMaterial({ map: tex, transparent: true, opacity: 0.85 });
  heightmapMesh = new THREE.Mesh(geom, mat);
  heightmapMesh.position.y = 1;
  scene.add(heightmapMesh);
  frameObject(heightmapMesh);
}

function fillSelect(select, items, getValue = (i) => i.path, getLabel = (i) => i.name) {
  select.innerHTML = "";
  for (const item of items) {
    const opt = document.createElement("option");
    opt.value = getValue(item);
    opt.textContent = getLabel(item);
    select.appendChild(opt);
  }
}

function populateCategorySelect() {
  const select = document.getElementById("category-select");
  select.innerHTML = "";
  for (const cat of CATEGORY_ORDER) {
    const list = assetsByCategory.get(cat) || [];
    if (!list.length) continue;
    const meta = assetIndex.categories?.[cat] || {};
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = `${meta.title || cat} (${list.length})`;
    select.appendChild(opt);
  }
}

function populateMeshSelect(category) {
  const list = assetsByCategory.get(category) || [];
  const select = document.getElementById("mesh-select");
  fillSelect(select, list, (a) => a.id, (a) => a.name);
  const desc = assetIndex.categories?.[category]?.description || "";
  document.getElementById("category-desc").textContent = desc;
  return list;
}

function findAsset(id) {
  for (const list of assetsByCategory.values()) {
    const hit = list.find((a) => a.id === id);
    if (hit) return hit;
  }
  return null;
}

function showTexture(relativePath) {
  showTextureUrl(`${OUT_BASE}${relativePath}`, relativePath);
}

function showTextureUrl(url, alt) {
  const el = document.getElementById("texture-preview");
  el.innerHTML = "";
  const img = document.createElement("img");
  img.src = url;
  img.alt = alt;
  el.appendChild(img);
}

async function selectCategory(category) {
  const list = populateMeshSelect(category);
  if (!list.length) return;
  const meshSelect = document.getElementById("mesh-select");
  let pick = list[0];
  if (category === "vehicles") {
    const preferred =
      assetIndex.assets?.find((a) => a.id === "car_096_core_assembly")?.id ||
      assetIndex.default_vehicle_asset_id ||
      assetIndex.assets?.find((a) => a.id === "car_096_assembly")?.id;
    if (preferred) {
      pick = findAsset(preferred) || pick;
    }
  }
  meshSelect.value = pick.id;
  await loadMesh(pick);
}

async function main() {
  initThree();
  try {
    const manifest = await loadManifest();
    assetIndex = buildAssetIndexFromManifest(manifest);
    indexAssets(assetIndex);

    populateCategorySelect();

    let startCategory = "track";
    let startAsset = null;
    if (assetIndex.default_asset_id) {
      for (const [cat, list] of assetsByCategory) {
        startAsset = list.find((a) => a.id === assetIndex.default_asset_id);
        if (startAsset) {
          startCategory = cat;
          break;
        }
      }
    }
    if (!startAsset) {
      const trackList = assetsByCategory.get("track") || [];
      startAsset = trackList[0] || assetIndex.assets?.[0];
    }

    document.getElementById("category-select").value = startCategory;
    populateMeshSelect(startCategory);
    if (startAsset) {
      document.getElementById("mesh-select").value = startAsset.id;
      await loadMesh(startAsset);
    }

    manifestTextures = manifest.textures || [];
    fillSelect(document.getElementById("heightmap-select"), manifest.heightmaps || []);
    fillSelect(
      document.getElementById("texture-select"),
      manifestTextures,
      (t) => t.path,
      (t) => t.name,
    );

    const labelList = document.getElementById("label-list");
    for (const label of (manifest.labels || []).slice(0, 200)) {
      const li = document.createElement("li");
      li.textContent = label;
      labelList.appendChild(li);
    }

    if (manifestTextures.length) {
      const preview =
        manifestTextures.find((t) => t.name.includes("palette_cb0")) ||
        manifestTextures.find((t) => t.name.includes("logical"));
      showTexture(preview?.path || manifestTextures[0].path);
    }

    document.getElementById("category-select").addEventListener("change", (e) => selectCategory(e.target.value));
    document.getElementById("mesh-select").addEventListener("change", (e) => {
      const asset = findAsset(e.target.value);
      if (asset) loadMesh(asset);
    });
    document.getElementById("y-min").addEventListener("input", rebuildMeshDisplay);
    document.getElementById("y-max").addEventListener("input", rebuildMeshDisplay);
    document.getElementById("z-min").addEventListener("input", rebuildMeshDisplay);
    document.getElementById("z-max").addEventListener("input", rebuildMeshDisplay);
    document.getElementById("display-mode").addEventListener("change", async (e) => {
      displayMode = e.target.value;
      if (
        texturedMeshObject &&
        currentAsset?.textured_path &&
        (displayMode === "textured" || displayMode === "uv-atlas")
      ) {
        await applyTexturedDisplayMode(texturedMeshObject, currentAsset, displayMode);
      }
      rebuildMeshDisplay();
    });
    document.getElementById("heightmap-select").addEventListener("change", (e) => loadHeightmap(e.target.value));
    document.getElementById("texture-select").addEventListener("change", (e) => showTexture(e.target.value));

    document.getElementById("layer-grid").addEventListener("change", (e) => {
      gridHelper.visible = e.target.checked;
    });
    document.getElementById("layer-axes").addEventListener("change", (e) => {
      axesHelper.visible = e.target.checked;
    });
    document.getElementById("layer-mesh").addEventListener("change", (e) => {
      meshGroup.visible = e.target.checked;
    });
    document.getElementById("layer-heightmap").addEventListener("change", async (e) => {
      if (!e.target.checked) {
        if (heightmapMesh) heightmapMesh.visible = false;
        return;
      }
      const sel = document.getElementById("heightmap-select");
      if (sel.value) {
        await loadHeightmap(sel.value);
        if (heightmapMesh) heightmapMesh.visible = true;
      }
    });
  } catch (err) {
    document.getElementById("sidebar").insertAdjacentHTML(
      "beforeend",
      `<p style="color:#f88">${err.message}</p>`
    );
  }
}

main();

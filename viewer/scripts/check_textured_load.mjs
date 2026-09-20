import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const THREE = require("three");
const { OBJLoader } = require("three/examples/jsm/loaders/OBJLoader.js");
const { MTLLoader } = require("three/examples/jsm/loaders/MTLLoader.js");

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const out = join(root, "out");
const objPath = join(out, "scenes/tracks/track_desert_textured.obj");
const mtlPath = join(out, "scenes/tracks/track_desert_textured.mtl");
const objText = readFileSync(objPath, "utf8");
const mtlText = readFileSync(mtlPath, "utf8");

const materials = new MTLLoader().parse(mtlText);
materials.preload();
for (const name of Object.keys(materials.materialsInfo || {})) {
  const info = materials.materialsInfo[name];
  const mat = materials.materials[name];
  console.log(name, "map", info.map_kd, "hasMap", Boolean(mat?.map), "img", mat?.map?.image?.width, mat?.map?.image?.height);
}

const loader = new OBJLoader();
loader.setMaterials(materials);
const obj = loader.parse(objText);

let meshes = 0;
let withUv = 0;
let withMap = 0;
let uvSample = null;
obj.traverse((child) => {
  if (!child.isMesh) return;
  meshes += 1;
  const uv = child.geometry?.attributes?.uv;
  const mat = Array.isArray(child.material) ? child.material[0] : child.material;
  if (uv) {
    withUv += 1;
    if (!uvSample) uvSample = [uv.getX(0), uv.getY(0), uv.getX(1), uv.getY(1)];
  }
  if (mat?.map) withMap += 1;
});
console.log("meshes", meshes, "withUv", withUv, "withMap", withMap, "uvSample", uvSample);

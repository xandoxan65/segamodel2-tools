"""Wavefront OBJ/MTL writers for mesh exports."""

from __future__ import annotations

from pathlib import Path

from tools.model2_texture import TexturedPrimitive, atlas_uv_to_patch_local


def palette_material_name(
    sheet_index: int,
    colorbase: int,
    lumabase: int,
    *,
    translucent: bool = False,
    checker: bool = False,
    patch_x: int = 0,
    patch_y: int = 0,
    patch_w: int = 0,
    patch_h: int = 0,
) -> str:
    suffix = "_tr" if translucent or checker else ""
    name = f"s{sheet_index}_cb{colorbase:03x}_lb{lumabase:04x}"
    if patch_w > 0 and patch_h > 0:
        name += f"_px{patch_x:04x}_py{patch_y:04x}_w{patch_w}h{patch_h}"
    return f"{name}{suffix}"


def solid_material_name(colorbase: int) -> str:
    return f"solid_cb{colorbase:03x}"


def _rel_to_obj(path: Path, obj_path: Path) -> str:
    try:
        return path.resolve().relative_to(obj_path.parent.resolve()).as_posix()
    except ValueError:
        import os

        return os.path.relpath(path, obj_path.parent).replace("\\", "/")


def _rel_to_out_root(path: Path, out_root: Path) -> str:
    """Path for map_Kd relative to export root (viewer publicDir = out/)."""
    try:
        return path.resolve().relative_to(out_root.resolve()).as_posix()
    except ValueError:
        import os

        return os.path.relpath(path, out_root).replace("\\", "/")


def build_solid_material_colors(
    primitives: list[TexturedPrimitive],
    *,
    palette,
) -> dict[str, tuple[float, float, float]]:
    """MAME draw_scanline_solid uses palram[colorbase] as a 15-bit RGB source."""
    solids: dict[str, tuple[float, float, float]] = {}
    keys = {
        prim.colorbase
        for prim in primitives
        if len(prim.indices) >= 3 and not (prim.renderer & 2)
    }
    for colorbase in sorted(keys):
        r, g, b = palette.lookup_rgb15(palette.pal_colorbase_entry(colorbase))
        solids[solid_material_name(colorbase)] = (r / 255.0, g / 255.0, b / 255.0)
    return solids


def build_palette_material_maps(
    primitives: list[TexturedPrimitive],
    *,
    palette,
    texture_sheets: tuple[list[int], list[int]],
    cache_dir: Path,
    obj_path: Path,
    out_root: Path | None = None,
) -> dict[str, str]:
    """Bake per-(sheet,colorbase,lumabase) tinted sheets; return MTL material map."""
    import shutil

    from PIL import Image

    from tools.extract.textures import decode_colored_logical_sheet

    if cache_dir.is_dir():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    materials: dict[str, str] = {}
    keys = {
        (
            prim.sheet_index,
            prim.colorbase,
            prim.lumabase,
            bool(prim.translucent),
            bool(prim.checker),
            prim.patch_x,
            prim.patch_y,
            prim.patch_w,
            prim.patch_h,
        )
        for prim in primitives
        if len(prim.indices) >= 3 and (prim.renderer & 2)
    }
    for (
        sheet_index,
        colorbase,
        lumabase,
        translucent,
        checker,
        patch_x,
        patch_y,
        patch_w,
        patch_h,
    ) in sorted(keys):
        cutout = translucent or checker
        name = palette_material_name(
            sheet_index,
            colorbase,
            lumabase,
            translucent=cutout,
            checker=checker,
            patch_x=patch_x,
            patch_y=patch_y,
            patch_w=patch_w,
            patch_h=patch_h,
        )
        png_name = f"{name}.png"
        png_path = cache_dir / png_name
        sheet = texture_sheets[sheet_index] if sheet_index < len(texture_sheets) else texture_sheets[0]
        rgba = decode_colored_logical_sheet(
            sheet,
            palette,
            colorbase=colorbase,
            lumabase=lumabase,
            cutout_transparent=translucent,
            checker_cutout=checker,
            cutout_background_zero=translucent and colorbase == 0x128,
        )
        if patch_w > 0 and patch_h > 0:
            rgba = rgba[patch_y : patch_y + patch_h, patch_x : patch_x + patch_w]
        Image.fromarray(rgba, mode="RGBA").save(png_path)
        root = out_root or obj_path.parent.parent.parent
        materials[name] = _rel_to_out_root(png_path, root)
    return materials


def texture_sheet_materials(
    obj_path: Path, out_root: Path, *, grayscale_indices: bool = False
) -> dict[str, str]:
    """Relative map_Kd paths for sheet0/sheet1 from an OBJ under out_root."""
    tex_dir = out_root / "textures"
    obj_dir = obj_path.parent.resolve()

    def pick_sheet(index: int) -> str:
        palette_name = f"sheet{index}_logical_2048x1024_palette_cb0.png"
        gray_name = f"sheet{index}_logical_2048x1024.png"
        if grayscale_indices:
            name = gray_name
        else:
            name = palette_name if (tex_dir / palette_name).is_file() else gray_name
        try:
            return Path(tex_dir / name).resolve().relative_to(obj_dir).as_posix()
        except ValueError:
            import os

            return os.path.relpath(tex_dir / name, obj_dir).replace("\\", "/")

    return {
        "sheet0": pick_sheet(0),
        "sheet1": pick_sheet(1),
    }


def write_obj(
    path: Path,
    vertices: list[tuple[float, float, float]],
    primitives: list[tuple[int, ...]] | None = None,
    *,
    face_normals: list[tuple[float, float, float]] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("# segamod2 Model 2 geo parser export\n")
        for x, y, z in vertices:
            f.write(f"v {x:.6f} {y:.6f} {z:.6f}\n")
        if face_normals:
            for nx, ny, nz in face_normals:
                f.write(f"vn {nx:.6f} {ny:.6f} {nz:.6f}\n")
        if primitives:
            for fi, face in enumerate(primitives):
                if face_normals and fi < len(face_normals):
                    ni = fi + 1
                    if len(face) == 3:
                        f.write(
                            f"f {face[0] + 1}//{ni} {face[1] + 1}//{ni} {face[2] + 1}//{ni}\n"
                        )
                    elif len(face) == 4:
                        f.write(
                            f"f {face[0] + 1}//{ni} {face[1] + 1}//{ni} "
                            f"{face[2] + 1}//{ni} {face[3] + 1}//{ni}\n"
                        )
                elif len(face) == 3:
                    f.write(f"f {face[0] + 1} {face[1] + 1} {face[2] + 1}\n")
                elif len(face) == 4:
                    f.write(
                        f"f {face[0] + 1} {face[1] + 1} {face[2] + 1} {face[3] + 1}\n"
                    )


def write_textured_obj(
    path: Path,
    vertices: list[tuple[float, float, float]],
    primitives: list[TexturedPrimitive],
    *,
    mtl_name: str,
    material_by_sheet: dict[int, str] | None = None,
    palette=None,
    texture_sheets: tuple[list[int], list[int]] | None = None,
    palette_cache_dir: Path | None = None,
    out_root: Path | None = None,
    index_sheets_only: bool = False,
) -> Path:
    """Write OBJ with UVs and companion MTL. Returns the MTL path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mtl_path = path.with_suffix(".mtl")
    material_by_sheet = material_by_sheet or {0: mtl_name, 1: f"{mtl_name}_sheet1"}
    palette_materials: dict[str, str] | None = None
    solid_materials: dict[str, tuple[float, float, float]] | None = None
    sheet_materials: dict[str, str] | None = None
    if index_sheets_only:
        root = out_root or path.parent.parent
        sheet_materials = texture_sheet_materials(path, root, grayscale_indices=True)
        write_mtl(mtl_path, sheet_materials)
    elif palette is not None and texture_sheets is not None and palette_cache_dir is not None:
        export_root = out_root or path.parent.parent.parent
        palette_materials = build_palette_material_maps(
            primitives,
            palette=palette,
            texture_sheets=texture_sheets,
            cache_dir=palette_cache_dir,
            obj_path=path,
            out_root=export_root,
        )
        solid_materials = build_solid_material_colors(primitives, palette=palette)
        alpha_mats = {n for n in palette_materials if n.endswith("_tr")}
        write_mtl(
            mtl_path,
            palette_materials,
            solid_colors=solid_materials,
            alpha_materials=alpha_mats,
        )

    texcoords: list[tuple[float, float]] = []
    face_lines: list[str] = []
    batches: dict[str, list[TexturedPrimitive]] = {}
    solid_primitives: list[tuple[str, TexturedPrimitive]] = []

    for prim in primitives:
        if len(prim.indices) < 3:
            continue
        textured = bool(prim.renderer & 2)
        if sheet_materials is not None:
            mat = "sheet1" if prim.sheet_index == 1 else "sheet0"
        elif palette_materials is not None:
            mat = (
                palette_material_name(
                    prim.sheet_index,
                    prim.colorbase,
                    prim.lumabase,
                    translucent=bool(prim.translucent or prim.checker),
                    checker=prim.checker,
                    patch_x=prim.patch_x,
                    patch_y=prim.patch_y,
                    patch_w=prim.patch_w,
                    patch_h=prim.patch_h,
                )
                if textured
                else solid_material_name(prim.colorbase)
            )
        else:
            mat = material_by_sheet.get(prim.sheet_index, mtl_name)
        if textured:
            batches.setdefault(mat, []).append(prim)
        else:
            solid_primitives.append((mat, prim))

    def emit_faces(prim: TexturedPrimitive, *, textured: bool) -> None:
        if textured:
            base_vt = len(texcoords)
            for u, v in prim.uvs[: len(prim.indices)]:
                texcoords.append(
                    atlas_uv_to_patch_local(
                        u,
                        v,
                        patch_x=prim.patch_x,
                        patch_y=prim.patch_y,
                        patch_w=prim.patch_w,
                        patch_h=prim.patch_h,
                    )
                )
            if len(prim.indices) == 3:
                a, b, c = (base_vt + i + 1 for i in range(3))
                i, j, k = (idx + 1 for idx in prim.indices)
                face_lines.append(f"f {i}/{a} {j}/{b} {k}/{c}")
            elif len(prim.indices) == 4:
                a, b, c, d = (base_vt + i + 1 for i in range(4))
                i, j, k, l = (idx + 1 for idx in prim.indices)
                face_lines.append(f"f {i}/{a} {j}/{b} {k}/{c} {l}/{d}")
        elif len(prim.indices) == 3:
            i, j, k = (idx + 1 for idx in prim.indices)
            face_lines.append(f"f {i} {j} {k}")
        elif len(prim.indices) == 4:
            i, j, k, l = (idx + 1 for idx in prim.indices)
            face_lines.append(f"f {i} {j} {k} {l}")

    for mat in sorted(batches):
        face_lines.append(f"o {mat}")
        face_lines.append(f"usemtl {mat}")
        for prim in batches[mat]:
            emit_faces(prim, textured=True)

    if solid_primitives:
        face_lines.append("o solid")
        active_mat: str | None = None
        for mat, prim in solid_primitives:
            if mat != active_mat:
                face_lines.append(f"usemtl {mat}")
                active_mat = mat
            emit_faces(prim, textured=False)

    with path.open("w", encoding="utf-8") as f:
        f.write("# segamod2 textured Model 2 export\n")
        f.write(f"mtllib {mtl_path.name}\n")
        for x, y, z in vertices:
            f.write(f"v {x:.6f} {y:.6f} {z:.6f}\n")
        for u, v in texcoords:
            f.write(f"vt {u:.6f} {v:.6f}\n")
        f.write("\n".join(face_lines))
        if face_lines:
            f.write("\n")

    return mtl_path


def write_mtl(
    path: Path,
    materials: dict[str, str],
    *,
    solid_colors: dict[str, tuple[float, float, float]] | None = None,
    alpha_materials: set[str] | None = None,
) -> None:
    """Write MTL with map_Kd texture paths (relative to OBJ)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    alpha_set = alpha_materials or set()
    with path.open("w", encoding="utf-8") as f:
        for name, texture_rel in materials.items():
            f.write(f"newmtl {name}\n")
            f.write("Ka 1.0 1.0 1.0\n")
            f.write("Kd 1.0 1.0 1.0\n")
            f.write("Ks 0.0 0.0 0.0\n")
            if name in alpha_set or name.endswith("_tr"):
                # RGBA map_Kd only — map_d would load alphaMap (red channel), not PNG alpha.
                f.write("d 1.0\n")
                f.write(f"map_Kd {texture_rel}\n\n")
            else:
                f.write("d 1.0\n")
                f.write(f"map_Kd {texture_rel}\n\n")
        for name, (r, g, b) in (solid_colors or {}).items():
            f.write(f"newmtl {name}\n")
            f.write("Ka 1.0 1.0 1.0\n")
            f.write(f"Kd {r:.6f} {g:.6f} {b:.6f}\n")
            f.write("Ks 0.0 0.0 0.0\n")
            f.write("d 1.0\n\n")

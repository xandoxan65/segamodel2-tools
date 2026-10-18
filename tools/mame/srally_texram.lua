-- Capture Sega Rally's texture RAM from MAME, for tools.extract.texture_ram --check.
--
--   mame srallyc -video none -sound none -nothrottle \
--        -autoboot_script tools/mame/srally_texram.lua
--
-- Model 2A packs a halfword per 32-bit write into the shares textureram0 and
-- textureram1 (model2.cpp tex0_w/tex1_w), so the first 1 MiB of each share,
-- read as little-endian words, is the sheet. This hashes a sample of both
-- sheets every frame and dumps whenever the hash settles on a new value,
-- naming each dump with the course variant (work RAM 0x214354) it was taken on.
-- The attract loop reaches variants 0 and 1 by itself.
--
-- env: TEXRAM_OUT (dir), TEXRAM_FRAMES (frames to run), TEXRAM_MAX (max dumps)

local OUT        = os.getenv("TEXRAM_OUT") or "."
local RUN_FRAMES = tonumber(os.getenv("TEXRAM_FRAMES") or "6000")
local MAX_DUMPS  = tonumber(os.getenv("TEXRAM_MAX") or "8")
local VARIANT    = 0x214354
local SHEET      = 0x100000
local SETTLE     = 30

local frames, lastHash, settleAt, dumps = 0, nil, -1, 0
local dumped = {}
local space, sheets

local function sampleHash()
    local h, nz = 5381, 0
    for _, s in ipairs(sheets) do
        for a = 0, SHEET - 1, 0x800 do
            local v = s:read_u32(a)
            h = (h * 33 + v) % 0x7fffffff
            if v ~= 0 then nz = nz + 1 end
        end
    end
    return h, nz
end

local function dumpShare(path, share)
    local f = assert(io.open(path, "wb"))
    local chunk = {}
    for a = 0, SHEET - 1, 4 do
        chunk[#chunk + 1] = string.pack("<I4", share:read_u32(a))
        if #chunk == 4096 then f:write(table.concat(chunk)); chunk = {} end
    end
    if #chunk > 0 then f:write(table.concat(chunk)) end
    f:close()
end

emu.register_frame_done(function()
    if not sheets then
        space = manager.machine.devices[":maincpu"].spaces["program"]
        local shares = manager.machine.memory.shares
        sheets = { shares[":textureram0"], shares[":textureram1"] }
    end
    frames = frames + 1
    local h, nz = sampleHash()
    if h ~= lastHash then lastHash = h; settleAt = frames + SETTLE end
    if frames == settleAt and nz > 64 and not dumped[h] then
        dumped[h] = true
        dumps = dumps + 1
        local variant = space:read_u32(VARIANT)
        local base = string.format("%s/srally_%02d_f%d_v%d", OUT, dumps, frames, variant)
        dumpShare(base .. "_sheet0.bin", sheets[1])
        dumpShare(base .. "_sheet1.bin", sheets[2])
        print(string.format("[texram] dump %d at frame %d, variant %d", dumps, frames, variant))
    end
    if dumps >= MAX_DUMPS or frames >= RUN_FRAMES then manager.machine:exit() end
end)

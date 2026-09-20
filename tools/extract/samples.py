"""Extract SCSP sample ROMs as raw PCM and short WAV previews."""

from __future__ import annotations

import struct
import wave
from pathlib import Path

from tools.rom_io import SRALLY_DATA_ROMS, load16_word_swap, resolve_rom_dir, write_bytes


# Model 2A SCSP: 16-bit PCM, 44.1 kHz (per Sega Retro / MAME driver notes).
SAMPLE_RATE = 44100


def extract_samples(rom_dir: Path, out_dir: Path, preview_seconds: float = 30.0) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for name in SRALLY_DATA_ROMS["samples"]:
        pcm = load16_word_swap(rom_dir, name)
        stem = Path(name).stem
        raw_path = out_dir / f"{stem}.pcm"
        write_bytes(raw_path, pcm)
        written.append(raw_path)

        # WAV uses signed 16-bit LE — ROM is already LE after word swap.
        preview_frames = int(SAMPLE_RATE * preview_seconds) * 2
        preview = pcm[:preview_frames]
        wav_path = out_dir / f"{stem}_preview.wav"
        with wave.open(str(wav_path), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(SAMPLE_RATE)
            wf.writeframes(preview)
        written.append(wav_path)

        # Simple waveform PNG via Pillow (optional quick look).
        try:
            import numpy as np
            from PIL import Image

            samples = np.frombuffer(preview, dtype="<i2")
            width = 2048
            height = 512
            chunk = len(samples) // width
            if chunk > 0:
                strip = samples[: width * chunk].reshape((chunk, width))
                lo, hi = float(strip.min()), float(strip.max())
                if hi > lo:
                    norm = ((strip.astype(np.float32) - lo) / (hi - lo) * 255.0).astype(np.uint8)
                else:
                    norm = np.zeros(strip.shape, dtype=np.uint8)
                png_path = out_dir / f"{stem}_waveform.png"
                Image.fromarray(norm, mode="L").save(png_path)
                written.append(png_path)
        except ImportError:
            pass

    manifest = out_dir / "manifest.txt"
    manifest.write_text(
        "Sega Rally sample ROM extract\n"
        f"rate_hz={SAMPLE_RATE}\n"
        f"preview_seconds={preview_seconds}\n"
        + "\n".join(SRALLY_DATA_ROMS["samples"])
        + "\n"
    )
    written.append(manifest)
    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Extract SCSP sample ROMs.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/samples"))
    parser.add_argument("--preview-seconds", type=float, default=30.0)
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_samples(rom_dir, args.out, args.preview_seconds)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()

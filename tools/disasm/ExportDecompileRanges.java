// Export decompiled functions in configured address ranges to JSON.
// @category segamod2

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportDecompileRanges extends GhidraScript {

    private static class Range {
        final long start;
        final long end;

        Range(long start, long end) {
            this.start = start;
            this.end = end;
        }

        boolean contains(long addr) {
            return addr >= start && addr < end;
        }
    }

    private int warningScore(String cSrc) {
        if (cSrc == null) {
            return 999;
        }
        int score = 0;
        score += count(cSrc, "/* WARNING") * 8;
        score += count(cSrc, "/* Duplicate") * 4;
        score += count(cSrc, "undefined4") * 2;
        score += count(cSrc, "undefined2") * 2;
        score += count(cSrc, "undefined1") * 2;
        score += count(cSrc, "undefined") * 3;
        score += count(cSrc, "->") * 1;
        score += count(cSrc, "goto") * 2;
        return score;
    }

    private int count(String haystack, String needle) {
        int n = 0;
        int idx = 0;
        while (true) {
            idx = haystack.indexOf(needle, idx);
            if (idx < 0) {
                return n;
            }
            n++;
            idx += needle.length();
        }
    }

    private String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private String preview(String cSrc) {
        if (cSrc == null) {
            return "";
        }
        return cSrc.length() <= 1200 ? cSrc : cSrc.substring(0, 1200);
    }

    private List<Range> parseRanges(String spec) {
        List<Range> ranges = new ArrayList<>();
        for (String part : spec.split(",")) {
            String[] se = part.split(":");
            long start = Long.parseLong(se[0].replace("0x", "").replace("0X", ""), 16);
            long end = Long.parseLong(se[1].replace("0x", "").replace("0X", ""), 16);
            ranges.add(new Range(start, end));
        }
        return ranges;
    }

    private boolean inRanges(long addr, List<Range> ranges) {
        for (Range range : ranges) {
            if (range.contains(addr)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        if (getScriptArgs().length < 2) {
            throw new IllegalArgumentException("Usage: ExportDecompileRanges.java <out.json> <start:end,...>");
        }

        String outPath = getScriptArgs()[0];
        List<Range> ranges = parseRanges(getScriptArgs()[1]);

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        StringBuilder json = new StringBuilder();
        json.append("[\n");
        boolean first = true;

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function func = it.next();
            long entry = func.getEntryPoint().getOffset();
            if (!inRanges(entry, ranges)) {
                continue;
            }

            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            boolean ok = res.decompileCompleted();
            String cSrc = null;
            String err = null;
            if (ok && res.getDecompiledFunction() != null) {
                cSrc = res.getDecompiledFunction().getC();
            } else {
                err = res.getErrorMessage();
            }

            if (!first) {
                json.append(",\n");
            }
            first = false;

            int lines = cSrc == null ? 0 : cSrc.split("\n", -1).length;
            json.append("  {\n");
            json.append("    \"name\": \"").append(jsonEscape(func.getName())).append("\",\n");
            json.append("    \"entry\": \"0x").append(String.format("%06x", entry)).append("\",\n");
            json.append("    \"size\": ").append(func.getBody().getNumAddresses()).append(",\n");
            json.append("    \"decompiled\": ").append(ok).append(",\n");
            json.append("    \"error\": ");
            if (err == null) {
                json.append("null");
            } else {
                json.append("\"").append(jsonEscape(err)).append("\"");
            }
            json.append(",\n");
            json.append("    \"warning_score\": ").append(warningScore(cSrc)).append(",\n");
            json.append("    \"c_lines\": ").append(lines).append(",\n");
            json.append("    \"c_preview\": \"").append(jsonEscape(preview(cSrc))).append("\",\n");
            json.append("    \"c\": ");
            if (cSrc == null) {
                json.append("null");
            } else {
                json.append("\"").append(jsonEscape(cSrc)).append("\"");
            }
            json.append("\n  }");
        }

        json.append("\n]\n");

        try (FileWriter fw = new FileWriter(outPath)) {
            fw.write(json.toString());
        }

        println("Wrote decompile export to " + outPath);
        ifc.dispose();
    }
}

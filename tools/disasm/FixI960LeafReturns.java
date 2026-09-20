// Mark i960 leaf return sequences: mov g14,gR; mov 0,g14; ... bx (gR).
// Ghidra treats bx (reg) as an indirect call; override to RETURN for decompilation.
// @category segamod2

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.scalar.Scalar;

public class FixI960LeafReturns extends GhidraScript {

    private boolean isG14(Register reg) {
        return reg != null && reg.getName().equalsIgnoreCase("g14");
    }

    private boolean isReturnScratch(Register reg) {
        if (reg == null) {
            return false;
        }
        String name = reg.getName().toLowerCase();
        if (!name.startsWith("g") || name.equals("g14")) {
            return false;
        }
        try {
            int n = Integer.parseInt(name.substring(1));
            return n >= 0 && n <= 15;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private boolean isLinkSaveMov(Instruction instr) {
        Register r0 = registerFromOperand(instr, 0);
        Register r1 = registerFromOperand(instr, 1);
        return isLinkSaveMov(r0, r1) || isLinkSaveMov(r1, r0);
    }

    private boolean isLinkSaveMov(Register src, Register dst) {
        return isG14(src) && isReturnScratch(dst);
    }

    private Register linkSaveDestination(Instruction instr) {
        Register r0 = registerFromOperand(instr, 0);
        Register r1 = registerFromOperand(instr, 1);
        if (isLinkSaveMov(r0, r1)) {
            return r1;
        }
        if (isLinkSaveMov(r1, r0)) {
            return r0;
        }
        return null;
    }

    private boolean isClearG14Mov(Instruction instr) {
        if (!instr.getMnemonicString().equalsIgnoreCase("mov")) {
            return false;
        }
        Register r0 = registerFromOperand(instr, 0);
        Register r1 = registerFromOperand(instr, 1);
        if (isZeroScalar(instr, 0) && isG14(r1)) {
            return true;
        }
        if (isZeroScalar(instr, 1) && isG14(r0)) {
            return true;
        }
        return false;
    }

    private Register registerFromOperand(Instruction instr, int opIndex) {
        Register reg = instr.getRegister(opIndex);
        if (reg != null) {
            return reg;
        }
        for (Object obj : instr.getOpObjects(opIndex)) {
            if (obj instanceof Register) {
                return (Register) obj;
            }
        }
        return null;
    }

    private boolean isZeroScalar(Instruction instr, int opIndex) {
        for (Object obj : instr.getOpObjects(opIndex)) {
            if (obj instanceof Scalar) {
                return ((Scalar) obj).getValue() == 0;
            }
        }
        return false;
    }

    private Register movDestination(Instruction instr) {
        Register saved = linkSaveDestination(instr);
        if (saved != null) {
            return saved;
        }
        Register r0 = registerFromOperand(instr, 0);
        Register r1 = registerFromOperand(instr, 1);
        if (r1 != null && isReturnScratch(r1)) {
            return r1;
        }
        if (r0 != null && isReturnScratch(r0)) {
            return r0;
        }
        return r1 != null ? r1 : r0;
    }

    private Register movSource(Instruction instr) {
        Register r0 = registerFromOperand(instr, 0);
        Register r1 = registerFromOperand(instr, 1);
        Register saved = linkSaveDestination(instr);
        if (saved != null) {
            return saved == r0 ? r1 : r0;
        }
        return r0;
    }

    private Register destinationRegister(Instruction instr) {
        String mnem = instr.getMnemonicString().toLowerCase();
        if (mnem.equals("mov") || mnem.equals("movl")) {
            return movDestination(instr);
        }
        int n = instr.getNumOperands();
        if (n <= 0) {
            return null;
        }
        Register last = registerFromOperand(instr, n - 1);
        if (last != null && isReturnScratch(last)) {
            return last;
        }
        return null;
    }

    private Register bxTarget(Instruction instr) {
        if (!instr.getMnemonicString().equalsIgnoreCase("bx")) {
            return null;
        }
        return registerFromOperand(instr, 0);
    }

    private String findPrologueLinkSave(Function func, int maxInsns) {
        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(func.getBody(), true);
        List<Instruction> prologue = new ArrayList<>();
        while (it.hasNext() && prologue.size() < maxInsns) {
            prologue.add(it.next());
        }

        for (int i = 0; i < prologue.size(); i++) {
            Instruction ins = prologue.get(i);
            if (!ins.getMnemonicString().equalsIgnoreCase("mov")) {
                continue;
            }
            Register dst = linkSaveDestination(ins);
            if (dst == null) {
                continue;
            }
            String saved = dst.getName().toLowerCase();
            for (int j = i + 1; j < Math.min(i + 6, prologue.size()); j++) {
                if (isClearG14Mov(prologue.get(j))) {
                    return saved;
                }
            }
        }
        return null;
    }

    private int fixFunction(Function func) {
        String linkReg = findPrologueLinkSave(func, 24);
        if (linkReg == null) {
            return 0;
        }

        int fixed = 0;
        boolean g14Cleared = false;
        boolean linkRegLive = true;
        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(func.getBody(), true);
        while (it.hasNext()) {
            Instruction instr = it.next();
            String mnem = instr.getMnemonicString().toLowerCase();

            if (mnem.equals("mov")) {
                Register dst = movDestination(instr);
                Register src = movSource(instr);
                if (isLinkSaveMov(instr) && dst != null && dst.getName().equalsIgnoreCase(linkReg)) {
                    linkRegLive = true;
                } else if (isClearG14Mov(instr)) {
                    g14Cleared = true;
                } else if (dst != null && dst.getName().equalsIgnoreCase(linkReg) && !isG14(src)) {
                    linkRegLive = false;
                }
            } else if (!mnem.equals("bx")) {
                Register dst = destinationRegister(instr);
                if (dst != null && dst.getName().equalsIgnoreCase(linkReg)) {
                    linkRegLive = false;
                }
            }

            Register target = bxTarget(instr);
            if (target != null
                    && target.getName().equalsIgnoreCase(linkReg)
                    && g14Cleared
                    && linkRegLive
                    && instr.getFlowOverride() != FlowOverride.RETURN) {
                instr.setFlowOverride(FlowOverride.RETURN);
                fixed++;
            }
        }
        return fixed;
    }

    @Override
    public void run() throws Exception {
        int tx = currentProgram.startTransaction("FixI960LeafReturns");
        int total = 0;
        Set<String> touched = new HashSet<>();
        try {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function func = it.next();
                int n = fixFunction(func);
                if (n > 0) {
                    touched.add(func.getName());
                    total += n;
                }
            }
        } finally {
            currentProgram.endTransaction(tx, true);
        }
        println("FixI960LeafReturns: marked " + total + " bx return(s) in " + touched.size() + " function(s)");
    }
}

#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import pickle
import logging
import time
from itertools import chain

OP_DST = 0
OP_SRC = 1
OP_SRC2 = 2

class Ok():
    def __init__(self, result):
        self.result = result

    def __repr__(self):
        return "<OK: {}>".format(self.result)

    def is_ok(self):
        return True

class Error():
    def __init__(self, result=""):
        self.result = result

    def __repr__(self):
        return "<Error: {}>".format(self.result)

    def is_ok(self):
        return False


# (instr: ghidra.program.database.code.InstructionDB) -> None
def loginstr(instr):
    if instr is not None:
        logger.debug('|- {} {}'.format(instr.getAddress(), instr))
    else:
        logger.debug('|- NONE')


def logsep():
    logger.debug('-'*80)


# (address: str) -> ghidra.program.database.code.InstructionDB
def get_at(address):
    addr_b = address.decode()
    for instr in currentProgram.getListing().getInstructions(True):
        if instr.getAddress().toString() == addr_b:
            return instr


# (program: ghidra.program.database.ProgramDB, instr_s: str | List[str] | fn ghidra.program.database.code.InstructionDB -> bool)
# -> List[ghidra.program.database.code.InstructionDB]
def find_instr(program, instr_s):
    all_instrs = program.getListing().getInstructions(True)
    if isinstance(instr_s, list):
        targets = [x.decode() for x in instr_s]
        found = [i for i in all_instrs if strip_suffix(i.getMnemonicString()) in targets]
    elif isinstance(instr_s, str):
        target = instr_s.decode()
        found = [i for i in all_instrs if strip_suffix(i.getMnemonicString()) == target]
    elif callable(instr_s):
        found = [i for i in all_instrs if instr_s(strip_suffix(i.getMnemonicString()))]
    else:
        found = []  # error can't happen
    return found


def strip_suffix(mnem):
    # type: (str) -> str
    if '.' in mnem:
        mnem = mnem[:mnem.index('.')]
    elif mnem[-1] == 'w':
        mnem = mnem[:-1]

    if mnem in ['adds', 'subs', 'ands', 'orrs', 'eors']:
        mnem = mnem[:-1]

    return mnem


# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_ldr(instr):
    mnem = instr.getMnemonicString()
    stripped = strip_suffix(mnem)
    return stripped.startswith('ldr') or stripped.startswith('ldm')

# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_str(instr):
    mnem = instr.getMnemonicString()
    stripped = strip_suffix(mnem)
    return any(stripped.startswith(s) for s in ['str', 'stm', 'swp'])

# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_pop(instr):
    mnem = instr.getMnemonicString()
    stripped = strip_suffix(mnem)
    return stripped.startswith('pop')


# Branch instructions taking register: bx, blx, bxj
# https://developer.arm.com/documentation/dui0489/c/Cihfddaf
# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_bx(instr):
    mnem = instr.getMnemonicString()
    return strip_suffix(mnem) in ['bx', 'blx', 'bxj']


# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_compare(instr):
    mnem = instr.getMnemonicString()
    return strip_suffix(mnem) in ['cbz', 'cbnz']


# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_mov(instr):
    mnem = instr.getMnemonicString()
    return strip_suffix(mnem).startswith('mov')


# (instr: ghidra.program.database.code.InstructionDB) -> bool
def is_fn_prologue(instr):
    mnem = instr.getMnemonicString()
    stripped = strip_suffix(mnem)
    if stripped == 'push':
        return True
    elif stripped == 'stmfd':
        return True
    return False

# (instr: ghidra.program.database.code.InstructionDB,
#  reg: ghidra.program.model.lang.Register)
# -> bool
def writes_reg(instr, reg):
    if instr is None:
        return False
    return reg in instr.getOpObjects(OP_DST)

# (instr: ghidra.program.database.code.InstructionDB,
#  opind: int)
# -> bool
def is_absolute_pointer(instr, opind):
    op = instr.getOpObjects(opind)
    if len(op) != 1:
        return False
    if not isinstance(op[0], ghidra.program.model.address.Address):
        return False
    return True

# (instr: ghidra.program.database.code.InstructionDB,
#  opind: int)
# -> VARIABLE (depends on operand)
def get_op(instr, opind):
    return instr.getOpObjects(opind)[0]


# (instr: ghidra.program.database.code.InstructionDB,
#  opind: int)
# -> bool
def is_reg_and_offset(instr, opind):
    op = instr.getOpObjects(opind)
    if len(op) != 2:
        return False
    reg, scal = op
    if not isinstance(reg, ghidra.program.model.lang.Register):
        return False
    if not isinstance(scal, ghidra.program.model.scalar.Scalar):
        return False
    return True


# (instr: ghidra.program.database.code.InstructionDB,
#  opind: int)
# -> Tuple[ghidra.program.model.lang.Register,
#          ghidra.program.model.scalar.Scalar]
def get_reg_and_offset(instr, opind):
    reg, scal = instr.getOpObjects(opind)
    return (reg, scal.getValue())

# (start_instr: ghidra.program.database.code.InstructionDB,
#  target_reg: ghidra.program.model.lang.Register)
# -> Ok[ghidra.program.database.code.InstructionDB] | Error
def backtrack_to_write(start_instr, target_reg):
    loginstr(start_instr)

    cur = start_instr.getPrevious()
    loginstr(cur)
    if not cur:
        return Error("No previous instruction")

    while True:
        # look for an instruction that writes into target_reg
        while not writes_reg(cur, target_reg):
            cur = cur.getPrevious()
            if not cur:
                return Error("No previous instruction")
            loginstr(cur)
        # we're at a previous instruction that uses the same register
        if is_ldr(cur):
            # we're at load!
            return Ok(cur)
        elif is_compare(cur):
            cur = cur.getPrevious()
            loginstr(cur)
        elif is_mov(cur):
            # e.g. mov r2,r0
            if cur.getRegister(OP_SRC):
                # switch to backtracking until the source register is written
                logger.debug('|- {} <- {} [new backtrack]'
                             .format(target_reg.getName(),
                                     cur.getRegister(OP_SRC).getName()))
                target_reg = cur.getRegister(OP_SRC)
                cur = cur.getPrevious()
                loginstr(cur)
            # e.g. mov 47, #0x20
            elif cur.getScalar(OP_SRC):
                # we're at mov scalar!
                return Ok(cur)
            else:
                logger.debug('not mov from register')
                return Error("Register written but can't figure out source")
        # other instructions are not useful for backtracking
        else:
            logger.debug('cannot backtrack from this instruction')
            return Error("could not backtrack from {}".format(cur))


# (addr: ghidra.program.model.address.GenericAddress)
# -> int
def deref(addr):
    return currentProgram.getMemory().getInt(addr)

def resolve_reg(start_instr, target_reg):
    # backtrack from start_instr, trying to resolve target_reg to a value

    # this is used as a stack
    offsets = []
    logsep()
    while True:
        # we have a branch to some other register
        # backtrack to a point where that register is being written
        instr_writing_reg_res = backtrack_to_write(start_instr, target_reg)
        if not instr_writing_reg_res.is_ok():
            # we reached a state we can't deal with yet (maybe wrong disassembly)
            # skip to next instruction
            return Error(instr_writing_reg_res.result)

        assert isinstance(instr_writing_reg_res, Ok), "Got {} instance with is_ok() as true".format(type(instr_writing_reg_res))
        instr_writing_reg = instr_writing_reg_res.result

        # we're at an instruction writing the register. could be a mov of
        # scalar, could be a load from absolute pointer, from offset on
        # register, or something else.
        # ldr target_reg, [0xwhatever] ≡ target_reg = *0xwhatever
        if is_mov(instr_writing_reg) and instr_writing_reg.getScalar(OP_SRC):
            value = start_instr.program.getImageBase().getNewAddress(instr_writing_reg.getScalar(OP_SRC).getValue())
            # if we have offsets, it's a deref chain:
            # *(*(*(0xvalue) + offset) + offset)
            try:
                for offset in offsets:
                    addr = deref(value)
                    deref_target = addr + offset
                    value = value.getNewAddress(deref_target)
                value = deref(value)
            except ghidra.program.model.mem.MemoryAccessException:
                # can't access the memory
                logger.debug("can't access memory address")
                return Error("can't access memory address")

            return Ok(value)

        elif is_absolute_pointer(instr_writing_reg, OP_SRC):
            value = instr_writing_reg.getOpObjects(OP_SRC)[0]
            # if we have offsets, it's a deref chain:
            # *(*(*0xwhatever + offset) + offset)
            try:
                for offset in offsets:
                    addr = deref(value)
                    deref_target = addr + offset
                    value = value.getNewAddress(deref_target)
                value = deref(value)
            except ghidra.program.model.mem.MemoryAccessException:
                # can't access the memory
                logger.debug("can't access memory address")
                return Error("can't access memory address")

            return Ok(value)

        # ldr target_reg, [some_reg, #offset]
        elif is_reg_and_offset(instr_writing_reg, OP_SRC):
            reg, offset = get_reg_and_offset(instr_writing_reg, OP_SRC)
            # keep track of offset
            offsets.insert(0, offset)
            # backtrack again, from instr_writing_reg with reg being new target
            logger.debug('new backtrack: {}'.format(reg))
            start_instr = instr_writing_reg
            target_reg = reg
            # iterate again
        else:
            # some other load we can't handle
            logger.debug("can't handle the source")
            return Error("can't handle the source")




logging.basicConfig()
logger = logging.getLogger(__name__)
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
logger.setLevel(LOGLEVEL)


# (program: ghidra.program.database.ProgramDB)
# -> List[int]
def get_abs_fn_ptrs(program):
    results = set()
    negatives = set()
    listing = program.getListing()
    for instruction in listing.getInstructions(True):
        # skip non-branching instrs
        if not is_bx(instruction):
            continue

        # found a branching instr, e.g. `bx r1`
        # skip if not branch to register
        target_reg = instruction.getRegister(OP_DST)
        if not target_reg:
            continue

        # skip if is link register (`bx lr` is basically `ret`)
        if target_reg.getName() == b'lr':
            continue

        func_addr = resolve_reg(instruction, target_reg)
        if not func_addr.is_ok():
            continue

        assert isinstance(func_addr, Ok), "Got instance of {} with is_ok() as true".format(type(func_addr))
        func_addr = func_addr.result

        if func_addr < 0:
            negatives.add(func_addr)
        else:
            if func_addr % 2 != 0:
                func_addr -= 1
            results.add(func_addr)

    if len(negatives) > 0:
        logger.warning("Warning: Got some negative addresses")
    return results


# (program: ghidra.program.database.ProgramDB)
# -> List[int]
def get_fn_prologues(program):
    prologues = set()
    for instr in program.getListing().getInstructions(True):
        if is_fn_prologue(instr):
            addr = instr.getAddress()
            prologues.add(int(addr.toString(), base=16))

    fm = program.getFunctionManager()
    for func in fm.getFunctions(True):  # True meaning forwards
        addr = func.getEntryPoint()
        prologues.add(int(addr.toString(), base=16))

    return prologues


# (program: ghidra.program.database.ProgramDB)
# -> Ok(int) | Error(str)
def find_base(program):
    abs_pointers = get_abs_fn_ptrs(program)
    if not abs_pointers:
        return Error('No absolute function pointers')

    prologues = get_fn_prologues(program)
    if not prologues:
        return Error('No function prologues')

    # this gives error: java.lang.OutOfMemoryError: java.lang.OutOfMemoryError: Java heap space
    #addr_space = range(0, min(abs_pointers))
    addr_space_end = min(abs_pointers)
    logger.debug("min of abs pointers: {}".format(addr_space_end))
    x = 0
    NF = dict()
    while x < addr_space_end:
        for p in abs_pointers:
            d = p - x
            if d in prologues:
                if x in NF:
                    NF[x] += 1
                else:
                    NF[x] = 1
        x += 1

    if not NF:
        return Error('NF is empty.')

    offset = max(NF, key=NF.get)
    return Ok(offset)

# (program: ghidra.program.database.ProgramDB,
#  addr: int)
# -> None
def rebase(program, addr):
    current_base = program.getImageBase()
    new_base = current_base.getNewAddress(addr)
    # false means no commit:
    # https://github.com/NationalSecurityAgency/ghidra/blob/849c6d195aebbd3700e54b4a223d5797244f90f3/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/ProgramDB.java#L1281
    program.setImageBase(new_base, False)
    analyzeAll(program)


# (program: ghidra.program.database.ProgramDB)
# -> ResultsType.ResultsMpuMemWrites
def get_mem_writes_refman(program):
    refman = program.getReferenceManager()
    mpu_mem_range = range(0xE000ED90,0xE000EDEC+1)
    mem_writes = []
    for a in mpu_mem_range:
        addr = program.getImageBase().getNewAddress(a)
        for ref in refman.getReferencesTo(addr):
            mem_writes.append({'src': int(ref.getFromAddress().toString(), base=16), 'to': int(ref.getToAddress().toString(), base=16)})
    return mem_writes

# (program: ghidra.program.database.ProgramDB)
# -> ResultsType.ResultsMpu
def analysis_mpu(program):
    # https://developer.arm.com/documentation/ddi0363/e/system-control-coprocessor/system-control-coprocessor-registers/c0--mpu-type-register?lang=en
    # To access the MPU Type Register, read CP15 with:
    # MRC p15, 0, <Rd>, c0, c0, 4 ; Returns MPU details
    candidates = find_instr(program, ['mrc', 'mcr'])
    # this is a brittle way to do it but I couldn't retrieve the first register via the API (getOpObjects, getRegister, etc.)
    mcrs = []
    for c in candidates:
        _, operands = c.toString().split(' ')
        operands = operands.split(',')
        if operands[0] == 'p15' and operands[1] == '0' and operands[3] == 'c0' and operands[4] == 'c0' and operands[5] == '4':
            mcrs.append(int(c.getAddress().toString(), base=16))

    logger.debug("mcrs: {}".format(mcrs))
    mem_writes = get_mem_writes_refman(program)

    logger.debug("Mem range writes {}".format(mem_writes))
    return Ok({'mcr': mcrs, 'mem_writes': mem_writes})


# (program: ghidra.program.database.ProgramDB)
# -> List[int]
def analysis_svc(program):
    # SVC
    # if there are multiple svc instr, OS present. if only one, must ensure
    # many incoming edges (like for a do_syscall function)
    svcs = find_instr(program, 'svc')
    svc_addresses = [int(i.getAddress().toString(), base=16) for i in svcs]
    return svc_addresses

# (program: ghidra.program.database.ProgramDB)
# -> List[Tuple[str, str, str]]
def analysis_xrefs(program):
    refman = program.getReferenceManager()
    start_addr = program.getImageBase().getNewAddress(0)
    xrefs = [(ref.getReferenceType().toString(),
              ref.getFromAddress().toString(),
              ref.getToAddress().toString())
             for ref in refman.getReferenceIterator(start_addr)]
    return xrefs

# (program: ghidra.program.database.ProgramDB, newbase: int | None)
# -> ResultsType.ResultsFileContents
def get_results(program, newbase=None):
    if newbase is None:
        base_results = find_base(program)
        logger.debug("base results: {}".format(base_results))
        if not base_results.is_ok():
            return Error(base_results.result)

        assert isinstance(base_results, Ok), "Got instance of {} with is_ok() as true".format(type(base_results))
        newbase = base_results.result

    logger.info("rebasing to: {}".format(newbase))
    rebase(program, newbase)

    svc_addresses = analysis_svc(program)
    xrefs = analysis_xrefs(program)
    mpu_mem_writes = analysis_mpu(program)

    if not mpu_mem_writes.is_ok():
        return Error(mpu_mem_writes.result)

    return Ok(dict(mpu=mpu_mem_writes.result,
                    xrefs=xrefs,
                    svc_addresses=svc_addresses,
                    base=newbase))


def main():
    logger.info("Starting at {}".format(time.ctime()))
    args = getScriptArgs()
    if len(args) < 2:
        raise SystemExit("Aguments: SHASUM RESULTS_DIR [BASE]")

    shasum = args[0]
    results_dir = args[1]

    program = currentProgram

    if len(args) == 3 and args[2] != '':
        the_results = get_results(program, int(args[2]))
    else:
        the_results = get_results(program)

    results = {'results': the_results.result, 'ok': the_results.is_ok(), 'sha': shasum}

    if not os.path.exists(results_dir):
        os.mkdir(results_dir)
    results_fname = "{}/{}.pkl".format(results_dir, shasum)
    with open(results_fname, 'wb') as resfile:
        pickle.dump(results, resfile)
    logger.info("results saved in {}".format(results_fname))


if __name__ == "__main__":
    main()
# https://github.com/HackOvert/GhidraSnippets/blob/master/README.md#find-all-calls-and-jumps-to-a-register
# https://ghidra.re/ghidra_docs/api/ghidra/program/database/code/InstructionDB.html
# https://developer.arm.com/documentation/dui0068/b/Writing-ARM-and-Thumb-Assembly-Language/Structure-of-assembly-language-modules/An-example-ARM-assembly-language-module

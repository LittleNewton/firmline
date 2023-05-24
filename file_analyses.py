# This file defines various file analysis functions
import bincopy
import binwalk
import hashlib
import itertools
import json
import logging
import multiprocessing, multiprocessing.connection
import os
import pickle
import r2pipe
import re
import subprocess
import tempfile
from binwalk.modules import signature as bw_signature, entropy as bw_entropy
from cpu_rec import which_arch2
from functools import wraps
from pathlib import Path
from statistics import median, mean
from typing import Callable, Union, TypedDict, Optional, List, Dict, Any, Tuple
import db
import reverse.ResultsType as RERes

logging.basicConfig()
logger = logging.getLogger(__name__)
LOGLEVEL = os.getenv('LOGLEVEL', 'INFO').upper()
logger.setLevel(LOGLEVEL)

class PaddingDict(TypedDict):
    zero: int
    ff: int

class BinwalkEntropy:
    def __init__(self, scan_result: Optional[bw_entropy.Entropy], timeout: bool=False):
        self.timeout = timeout
        if timeout:
            self.numbers, self.median, self.mean = None, None, None
        else:
            assert isinstance(scan_result, bw_entropy.Entropy), f"BinwalkEntropy called with wrong argument. Expected bw_entropy.Entropy, got {type(scan_result)}"
            numbers: List[float] = [float(re.sub('[)(]', '', x.description.split()[-1])) for x in scan_result.results]
            if not numbers:
                self.numbers, self.median, self.mean = None, None, None
            else:
                self.numbers = numbers
                self.median = median(self.numbers)
                self.mean = mean(self.numbers)

class BinwalkSignature:
    def __init__(self, scan_result: Optional[bw_signature.Signature], timeout: bool = False):
        self.timeout = timeout
        if timeout:
            self.types, self.found_linux = None, None
        else:
            assert isinstance(scan_result, bw_signature.Signature), f"BinwalkSignature called with wrong argument. Expected bw_signature.Signature, got {type(scan_result)}"
            types: List[str] = [r.description for r in scan_result.results]
            if not types:
                self.types = None
                self.found_linux = False
            else:
                self.types = types
                self.found_linux = found_linux(self.types)

class R2Results:
    def __init__(self, *, arch_supported: bool, timeout: bool, functions: Optional[Dict]):
        self.arch_supported: bool = arch_supported
        self.timeout: bool = timeout
        self.functions: Optional[Dict] = functions

        if functions is None:
            self.nfunctions = None
        else:
            maxes_per_arch = []
            for arch in functions:
                maxes_per_bits = []
                for bits in functions[arch]:
                    num_funcs_per_endian = []
                    for endian in functions[arch][bits]:
                        afl: List = functions[arch][bits][endian]
                        num_funcs_per_endian.append(len(afl))
                    max_for_bits = max(num_funcs_per_endian)
                    maxes_per_bits.append(max_for_bits)
                max_for_arch = max(maxes_per_bits)
                maxes_per_arch.append(max_for_arch)
            max_for_sample = max(maxes_per_arch)
            self.nfunctions = max_for_sample

# Timeout decorator

# Need this to be able to pickle the function for multiprocessing.Process
# see https://stackoverflow.com/questions/70002454/how-to-implement-a-multiprocessing-python-decorator
original_functions = {}
def func_runner(name: str, *args, **kwargs) -> Any:
    return original_functions[name](*args, **kwargs)

TimeoutRT = Union[int, Dict, BinwalkEntropy, BinwalkSignature, Optional[List]]
def timeout(n: float) -> Callable[[Callable[..., TimeoutRT]], Callable[..., TimeoutRT]]:
    def decorate(func: Callable[..., TimeoutRT]) -> Callable[..., TimeoutRT]:
        original_functions[func.__name__] = func
        @wraps(func)
        def wrapper(*args, **kwargs) -> TimeoutRT:
            rcv, snd = multiprocessing.Pipe()
            p = multiprocessing.Process(target=func_runner, args=(func.__name__, *args), kwargs={'snd': snd, **kwargs})
            p.start()

            p.join(timeout=n)

            if p.is_alive():
                p.terminate()
                p.join(timeout=10)
                if p.is_alive():
                    p.kill()
                    p.join()
            assert p.exitcode is not None, "Somehow the subprocess still hasn't exited."
            if p.exitcode == 0:
                result = rcv.recv()
                rcv.close()
                return result
            else:
                return p.exitcode
        return wrapper
    return decorate


def sha256(path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def arch(path: Path) -> Optional[List[str]]:
    logging.info(f'Checking arch for {path}...')
    with open(path, 'rb') as fh:
        identified_arch = which_arch2(fh.read())
    logging.info('Done')
    return identified_arch

def is_ihex(path: Path):
    scan_result = binwalk.scan(str(path), signature=True, quiet=True)
    assert len(scan_result) == 1, f"Binwalk scan returned results for {len(scan_result)} instead of 1 module."
    signature, *_ = scan_result

    return any("Intel HEX data" in r.description for r in signature.results)

def convert_ihex(path: Path) -> Path:
    newpath = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    ipt = bincopy.BinFile(str(path))
    newpath.write(ipt.as_binary())
    newpath.close()
    return Path(newpath.name)

def entropy(path: Path, timeout_sec: Optional[int] = 5*60) -> BinwalkEntropy:
    assert timeout_sec is not None
    @timeout(timeout_sec)
    def do_entropy_scan(*, snd: Optional[multiprocessing.connection.Connection]=None) -> BinwalkEntropy:
        scan_result = binwalk.scan(str(path), entropy=True, quiet=True, nplot=True)
        assert len(scan_result) == 1, f"Binwalk scan returned results for {len(scan_result)} instead of 1 module."
        entropy, *_ = scan_result
        entropy_instance = BinwalkEntropy(entropy)
        if snd:
            snd.send(entropy_instance)
            snd.close()
        return entropy_instance

    scan_result: TimeoutRT = do_entropy_scan()
    if isinstance(scan_result, int):
        return BinwalkEntropy(None, timeout=True)
    else:
        assert isinstance(scan_result, BinwalkEntropy), f"Got wrong return type for do_entropy_scan. Expected bw_entropy.Entropy, got {type(scan_result)}"
        return scan_result


def first_bytes(path: Path) -> bytes:
    # 100 words, word size depends on arch so choosing 8
    n_bytes = 8*100
    with open(path, 'rb') as f:
        res = f.read(n_bytes)
    return res

def found_linux(binwalk_types: List[str]) -> bool:
    terms = ['uimage', 'u-boot', 'squashfs', 'linux']

    for term in terms:
        if any(term.lower() in bwt.lower() for bwt in binwalk_types):
            return True

    if any('filesystem' in t.lower()
           and not re.match('^.*, from [^,]* filesystem', t)
           for t in binwalk_types):
        return True

    return False


def binwalk_signature(path: Path, timeout_sec: Optional[int] = 10*60) -> BinwalkSignature:
    assert timeout_sec is not None
    @timeout(timeout_sec)
    def do_signature_scan(*, snd: Optional[multiprocessing.connection.Connection]=None) -> BinwalkSignature:
        scan_result = binwalk.scan(str(path), signature=True, quiet=True)
        assert len(scan_result) == 1, f"Binwalk scan returned results for {len(scan_result)} instead of 1 module."
        signature_res, *_ = scan_result
        signature = BinwalkSignature(signature_res)
        if snd:
            snd.send(signature)
            snd.close()
        return signature

    scan_result: TimeoutRT = do_signature_scan()
    if isinstance(scan_result, int):
        return BinwalkSignature(scan_result=None, timeout=True)
    assert isinstance(scan_result, BinwalkSignature), f"Got wrong return type for do_signature_scan. Expected bw_signature.Signature, got {type(scan_result)}"
    return scan_result

def size(path: Path) -> int:
    return os.path.getsize(path)

def file_output(path) -> str:
    out = subprocess.check_output(['file', path])
    res = b''.join(out.strip().split(b': ')[1:]).decode()
    return res

def padding(path: Path) -> PaddingDict:
    result = PaddingDict(zero=0, ff=0)
    bstr_len = 8*4  # look for 4 groups of 8 bytes, then padding?

    bstr = '00'*bstr_len

    # output from bgrep is in the format:
    # /bin/ls: 000202d0
    res = subprocess.check_output(['bgrep', bstr, path])
    res = res.strip().decode('utf-8')
    if not res:
        result['zero'] = 0
    else:
        result['zero'] = len([x.split(": ")[1] for x in res.split("\n")])

    bstr = 'ff'*bstr_len
    res = subprocess.check_output(['bgrep', bstr, path])
    res = res.strip().decode('utf-8')
    if not res:
        result['ff'] = 0
    else:
        result['ff'] = len([x.split(": ")[1] for x in res.split("\n")])
    return result

def r2_cpurec(path: Path, path_arch: Optional[str], timeout_sec: Optional[int] = 10*60) -> R2Results:
    if path_arch is None:
        return R2Results(arch_supported=False, timeout=False, functions=None)

    ArchSpec = Tuple[str, int, str]
    def combine(archs: List[str], bits: List[int], endian: List[str]) -> List[ArchSpec]:
        return list(itertools.product(archs, bits, endian))

    cpurec_mappings: Dict[str, List[ArchSpec]] = {
        "ARMhf": (combine(['arm'], [16, 32], ['LE'])),
        "ARMel": (combine(['arm'], [16, 32], ['LE'])),
        'ARMeb': (combine(['arm'], [16, 32], ['BE'])),
        "6502": (combine(['6502.vasm'], [8, 16, 32, 64], ['LE'])),
        "X86-64": (combine(['x86.as', 'x86'], [64], ['LE'])),
        "ARM64": (combine(['arm'], [64], ['LE', 'BE'])),
        "X86": ((combine(['x86'], [8, 16, 32, 64], ['LE'])
            + combine(['x86.as', 'x86.nasm', 'x86.nz'], [16, 32, 64], ['LE']))),
        "Xtensa": (combine(['xtensa'], [32], ['LE', 'BE'])),
        'MIPSeb': (combine(['mips'], [16, 32, 64], ['BE']) + [('mips.gnu', 32, 'BE')]),
        'MIPSel': (combine(['mips'], [16, 32, 64], ['LE']) + [('mips.gnu', 32, 'LE')]),
        'SuperH': (combine(['sh'], [32], ['BE', 'LE'])),
        'AVR': (combine(['avr'], [8, 16], ['LE'])),
        'ARcompact': (combine(['arc'], [16, 32], ['BE', 'LE'])),
        'ARC32eb': [('arc', 32, 'BE')],
        'ARC32el': [('arc', 32, 'LE')],
        'SPARC': (combine(['sparc', 'sparc.gnu'], [32, 64], ['BE', 'LE'])),
        '8051': (combine(['8051'], [8, 16], ['BE', 'LE'])),
        'VAX': [('vax', 32, 'LE')],
        'MSP430': [('mps430', 16, 'LE')],
        'RISC-V': (combine(['riscv'], [32, 64], ['LE'])),
        'ARC32eb': [('arc', 32, 'BIG')],
        'PIC24': combine(['pic'], [24], ['LE', 'BE']),
        'PIC10': combine(['pic'], [12], ['LE', 'BE'])
    }

    # If not supported
    if not path_arch in cpurec_mappings:
        return R2Results(arch_supported=False, timeout=False, functions=None)
    # If supported
    else:
        logging.info(f"Running radare2 with {path_arch} for {path}")
        options = cpurec_mappings[path_arch]
        function_dict = dict()
        for arch, bits, endian in options:
            assert timeout_sec is not None
            @timeout(timeout_sec)
            def do_r2_analysis(*, snd: Optional[multiprocessing.connection.Connection]=None) -> Optional[List]:
                r2 = r2pipe.open(str(path))
                r2.cmd(f'e asm.arch={arch}')
                r2.cmd(f'e asm.bits={bits}')
                r2.cmd(f"e cfg.bigendian={'true' if endian == 'BE' else 'false'}")
                r2.cmd('aaaa')
                r2.cmd('aab')
                afl = r2.cmd('aflj')
                if afl is not None:
                    afl = json.loads(afl)
                r2.quit()
                if snd:
                    snd.send(afl)
                    snd.close()
                return afl

            r2_results: TimeoutRT = do_r2_analysis()
            if isinstance(r2_results, int):
                # timeout
                pass
            else:
                # no timeout
                if arch not in function_dict:
                    function_dict[arch] = dict()
                if bits not in function_dict[arch]:
                    function_dict[arch][bits] = dict()

                assert isinstance(r2_results, List), f"Got wrong return type for do_r2_analysis. Expected Dict, got {type(r2_results)}"
                function_dict[arch][bits][endian] = r2_results

        # If function_dict is empty, all of them timed out
        if not bool(function_dict):
            return R2Results(arch_supported=True, timeout=True, functions=None)
        # Otherwise, something didn't time out and we have a result
        else:
            return R2Results(arch_supported=True, timeout=False, functions=function_dict)


def ghidra_analyze_arch(filename: Path, sum: str, ghidra_arch: str, timeout_sec_term: Optional[int], timeout_sec_kill: Optional[int], base: Optional[int] = None) -> Optional[db.Ghidra]:
    # timeout(1) sends these signals:
    class Timeout1Signal:
        TERM = 124
        KILL = 137

    env = {'TIMEOUT_TERM': str(timeout_sec_term),
            'TIMEOUT_KILL': str(timeout_sec_kill),
            'GHIDRA_HOME': os.getenv('GHIDRA_HOME')}


    reverse_dir = Path('reverse/')
    assert reverse_dir.is_dir(), 'Reverse engineering code should be located in ./reverse, but that directory was not found.'
    results_dir = reverse_dir/'results'
    if not results_dir.is_dir():
        results_dir.mkdir(parents=True)
    results_file = results_dir/f"{sum}.pkl"
    if base is not None:
        logger.info(f"IHEX file, using base {base}")
        status = subprocess.call(['./run.sh', filename.absolute(), ghidra_arch, results_dir.absolute(), str(base)], cwd=reverse_dir, env=env)
    else:
        status = subprocess.call(['./run.sh', filename.absolute(), ghidra_arch, results_dir.absolute()], cwd=reverse_dir, env=env)
    if status == 0:
        with open(results_file, 'rb') as f:
            result: RERes.ResultsFileContents = pickle.load(f)
        assert result['sha'] == sum, f"Mismatch between shasum of argument and shasum of RE results {results_file}. Expected {sum}, got {result['sha']}."
        if result['ok']:
            assert isinstance(result['results'], Dict), f"RE results file does not contain an entry with results. Expected RERes.Results, got {type(result['results'])}"
            return db.Ghidra(
                    sum=sum,
                    base=result['results']['base'],
                    svc_addrs=db.prepare_obj(result['results']['svc_addresses']),
                    n_svc_addrs=len(result['results']['svc_addresses']),
                    xrefs=db.prepare_obj(result['results']['xrefs']),
                    n_xrefs=len(result['results']['xrefs']),
                    mcr=db.prepare_obj(result['results']['mpu']['mcr']),
                    mem_writes=db.prepare_obj(result['results']['mpu']['mem_writes']),
                    failed=False,
                    timeout=False)
        else:
            assert isinstance(result['results'], str), f"Got RE result error that does not have an error message. Expected results key with value str, got value {type(result['results'])}."
            return db.Ghidra(
                    sum=sum,
                    failed=True,
                    message=result['results'],
                    timeout=False)

    elif status in [Timeout1Signal.TERM, Timeout1Signal.KILL]:
        return db.Ghidra(
                sum=sum,
                failed=True,
                timeout=True)
    else:
        return None

# The run.sh script has a built-in timeout
def ghidra_analyze(filename: Path, sum: str, cpu_rec_arch: Optional[str], base: Optional[int] = None, timeout_sec_term: Optional[int] = 30*60, timeout_sec_kill: Optional[int] = 10*60) -> Optional[db.Ghidra]:

    # Mapping from cpu_rec architectures to Ghidra language defs
    # for ARM, we choose the most generic ones, try each of them, and tiebreak on number of xrefs
    arch_mappings = {
            'ARMhf': ['ARM:LE:32:Cortex'],
            'ARMel': ['ARM:LE:32:Cortex'],
            'ARMeb': ['ARM:BE:32:Cortex'],
            'ARM64': ['AARCH64:LE:64:v8A', 'AARCH64:LE:32:ilp32']
    }

    if cpu_rec_arch not in arch_mappings:
        return None

    results = [ghidra_analyze_arch(filename, sum, arch, timeout_sec_term, timeout_sec_kill, base=base) for arch in arch_mappings[cpu_rec_arch]]

    # If there's only 1 result, return it
    if len(results) == 1:
        return results[0]

    # If we didn't get analysis data, no point proceeding
    if all(r is None for r in results):
        return None

    results = [r for r in results if r is not None]

    # If all failed, return the first since it doesn't matter
    if all(r.failed for r in results):
        return results[0]

    # Remove failures
    results = [r for r in results if not r.failed]

    # If all timed out, return the first since it doesn't matter
    if all(r.timeout for r in results):
        return results[0]

    # Remove timeouts
    results = [r for r in results if not r.timeout]

    # There's at least one that did not fail or time out.
    # Tiebreak on number of xrefs.
    best_result = max(results, key=lambda x: x.n_xrefs if x.n_xrefs else 0)

    return best_result

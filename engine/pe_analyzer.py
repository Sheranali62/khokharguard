"""Khokhar & Son's Antivirus - safe PE (Portable Executable) analyzer.

Parses PE headers, sections, imports, and metadata WITHOUT executing
anything (spec section 17). Uses only safe structured reads of the
file bytes. Produces heuristic indicators that feed the risk engine.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from utils import get_logger

logger = get_logger("pe_analyzer")

# Import DLL/function names considered noteworthy. Presence alone is a
# weak indicator - weighted accordingly by the risk engine.
SUSPICIOUS_IMPORT_KEYWORDS = {
    "virtualalloc", "virtualprotect", "writeprocessmemory",
    "createremotethread", "ntunmapviewofsection", "setwindowshookex",
    "getasynckeystate", "winexec", "shellexecute", "urlmon",
    "urldownloadtofile", "wininet", "winhttp", "socket", "wsastartup",
    "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
    "loadlibrary", "getprocaddress", "setfiletime", "createtoolhelp32snapshot",
}

# Standard section names; unknown names are only a weak indicator.
KNOWN_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
    ".reloc", ".tls", ".debug", ".pdata", ".xdata", ".edata", ".gfids",
    ".ghelper", ".didat", ".CLR", "BSS",
}


@dataclass
class SectionInfo:
    """Parsed PE section details."""

    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    writable: bool
    executable: bool
    characteristics: int
    virtual_address: int = 0
    raw_pointer: int = 0


@dataclass
class PEInfo:
    """Complete parsed PE metadata for one file."""

    is_pe: bool = False
    valid: bool = False
    architecture: str = ""
    machine: int = 0
    entry_point: int = 0
    image_base: int = 0
    compile_timestamp: int = 0
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports_count: int = 0
    has_digital_signature: bool = False
    has_version_info: bool = False
    overlays_after_sections: bool = False
    error: str = ""

    def indicators(self) -> Dict[str, object]:
        """Suspicious indicators derived from parsed fields."""
        out: Dict[str, object] = {
            "high_entropy_sections": [],
            "writable_exec_sections": [],
            "suspicious_imports": [],
            "unknown_section_names": [],
            "unsigned": not self.has_digital_signature,
            "no_version_info": not self.has_version_info,
        }
        for section in self.sections:
            if section.entropy >= 7.2 and section.raw_size > 4096:
                out["high_entropy_sections"].append(section.name)
            if section.writable and section.executable:
                out["writable_exec_sections"].append(section.name)
            if section.name not in KNOWN_SECTION_NAMES and section.name != "":
                out["unknown_section_names"].append(section.name)
        for imp in self.imports:
            lowered = imp.lower()
            if any(keyword in lowered for keyword in SUSPICIOUS_IMPORT_KEYWORDS):
                out["suspicious_imports"].append(imp)
        return out


def compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


class PEAnalyzer:
    """Structural PE parser with suspicious-indicator extraction."""

    def analyze(self, path: Path) -> PEInfo:
        """Parse a PE file safely (reads only; never executes)."""
        info = PEInfo()
        try:
            data = path.read_bytes() if path.stat().st_size < 16 * 1024 * 1024 else None
        except OSError as exc:
            info.error = str(exc)
            return info

        if data is None:
            # Very large PE: read bounded windows instead of whole file.
            return self._analyze_large(path, info)
        return self._parse(data, info, path=path)

    # ------------------------------------------------------------------
    # Parsing internals
    # ------------------------------------------------------------------

    def _analyze_large(self, path: Path, info: PEInfo) -> PEInfo:
        """Bounded analysis for PEs larger than the full-read threshold."""
        try:
            with open(path, "rb") as fh:
                header = fh.read(4096)
            if not header.startswith(b"MZ"):
                info.error = "not a PE file"
                return info
            e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
            if e_lfanew + 1024 > len(header):
                fh.seek(e_lfanew)
                header = fh.read(e_lfanew + 1024)
            info.is_pe = True
            self._parse_headers(header, info)
        except (OSError, struct.error) as exc:
            info.error = str(exc)
        return info

    def _parse(self, data: bytes, info: PEInfo,
               path: Optional[Path] = None) -> PEInfo:
        """Parse full in-memory PE bytes."""
        if not data.startswith(b"MZ"):
            info.error = "not a PE file"
            return info
        info.is_pe = True
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                info.error = "missing PE signature"
                return info
            info.machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            info.compile_timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
            size_of_optional = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            opt_start = e_lfanew + 24
            magic = struct.unpack_from("<H", data, opt_start)[0]
            if magic == 0x10B:
                info.architecture = "x86 (PE32)"
                info.image_base = struct.unpack_from("<I", data, opt_start + 28)[0]
                info.entry_point = struct.unpack_from("<I", data, opt_start + 16)[0]
            elif magic == 0x20B:
                info.architecture = "x64 (PE32+)"
                info.image_base = struct.unpack_from("<Q", data, opt_start + 24)[0]
                info.entry_point = struct.unpack_from("<I", data, opt_start + 16)[0]
            else:
                info.architecture = f"unknown (magic {magic:#x})"

            sec_table = opt_start + size_of_optional
            for i in range(min(num_sections, 96)):
                offset = sec_table + i * 40
                if offset + 40 > len(data):
                    break
                name_bytes = data[offset:offset + 8].rstrip(b"\x00")
                name = name_bytes.decode("ascii", errors="replace")
                vsize, vaddr, rawsize, rawptr = struct.unpack_from(
                    "<IIII", data, offset + 8
                )
                chars = struct.unpack_from("<I", data, offset + 36)[0]
                section_data = data[rawptr:rawptr + min(rawsize, 1024 * 1024)]
                info.sections.append(
                    SectionInfo(
                        name=name,
                        virtual_size=vsize,
                        raw_size=rawsize,
                        entropy=compute_entropy(section_data),
                        writable=bool(chars & 0x80000000),
                        executable=bool(chars & 0x20000000),
                        characteristics=chars,
                        virtual_address=vaddr,
                        raw_pointer=rawptr,
                    )
                )

            self._parse_data_directories(data, e_lfanew, opt_start, info, magic)
            info.valid = True
        except struct.error as exc:
            info.error = f"malformed PE: {exc}"
            logger.debug("Malformed PE %s: %s",
                         getattr(path, "name", "<memory>"), exc)
        return info

    def _parse_headers(self, header: bytes, info: PEInfo) -> None:
        """Parse headers from a bounded buffer (large-file path)."""
        try:
            e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
            if header[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                info.error = "missing PE signature"
                return
            info.machine = struct.unpack_from("<H", header, e_lfanew + 4)[0]
            info.compile_timestamp = struct.unpack_from("<I", header, e_lfanew + 8)[0]
            num_sections = struct.unpack_from("<H", header, e_lfanew + 6)[0]
            size_of_optional = struct.unpack_from("<H", header, e_lfanew + 20)[0]
            opt_start = e_lfanew + 24
            magic = struct.unpack_from("<H", header, opt_start)[0]
            if magic == 0x10B:
                info.architecture = "x86 (PE32)"
            elif magic == 0x20B:
                info.architecture = "x64 (PE32+)"
            sec_table = opt_start + size_of_optional
            for i in range(min(num_sections, 96)):
                offset = sec_table + i * 40
                if offset + 40 > len(header):
                    break
                name = header[offset:offset + 8].rstrip(b"\x00").decode(
                    "ascii", errors="replace"
                )
                vsize, _vaddr, rawsize, _rawptr = struct.unpack_from(
                    "<IIII", header, offset + 8
                )
                chars = struct.unpack_from("<I", header, offset + 36)[0]
                info.sections.append(
                    SectionInfo(
                        name=name, virtual_size=vsize, raw_size=rawsize,
                        entropy=0.0,  # section bodies not read for huge files
                        writable=bool(chars & 0x80000000),
                        executable=bool(chars & 0x20000000),
                        characteristics=chars,
                    )
                )
            info.valid = True
        except struct.error as exc:
            info.error = f"malformed PE: {exc}"

    def _parse_data_directories(
        self, data: bytes, e_lfanew: int, opt_start: int,
        info: PEInfo, magic: int,
    ) -> None:
        """Extract imports/exports/signature presence indicators."""
        try:
            dd_offset = opt_start + 96  # data directory start (PE32 and PE32+)
            # Certificate entry is directory index 4
            _cert_rva, cert_size = struct.unpack_from("<II", data, dd_offset + 32)
            info.has_digital_signature = cert_size > 0

            # Import directory is index 1
            import_rva, _import_size = struct.unpack_from("<II", data, dd_offset + 8)
            if import_rva:
                self._parse_imports(data, import_rva, info)

            # Export directory is index 0
            export_rva, _export_size = struct.unpack_from("<II", data, dd_offset)
            info.exports_count = 1 if export_rva else 0

            # Version info resource presence (index 2 = resource dir)
            resource_rva, _resource_size = struct.unpack_from("<II", data, dd_offset + 16)
            if resource_rva:
                info.has_version_info = self._has_version_resource(data, resource_rva, info)
        except (struct.error, IndexError) as exc:
            logger.debug("Data directory parse failed: %s", exc)
            # Import directory is index 1
            import_rva, import_size = struct.unpack_from("<II", data, dd_offset + 8)
            if import_rva and import_size:
                self._parse_imports(data, import_rva, info)
        except (struct.error, IndexError) as exc:
            logger.debug("Data directory parse failed: %s", exc)

    def _parse_imports(self, data: bytes, import_rva: int, info: PEInfo) -> None:
        """Walk the import table (best effort, RVA->file offset naive)."""
        try:
            offset = self._rva_to_offset_naive(data, import_rva, info)
            if offset is None:
                return
            seen = 0
            while seen < 64:
                ilt_rva, _ts, _fc, name_rva = struct.unpack_from(
                    "<IIII", data, offset + seen * 20
                )
                if ilt_rva == 0 and name_rva == 0:
                    break
                dll_off = self._rva_to_offset_naive(data, name_rva, info)
                if dll_off is not None and dll_off + 1 < len(data):
                    end = data.find(b"\x00", dll_off)
                    dll_name = data[dll_off:end].decode("ascii", errors="replace")
                    info.imports.append(dll_name)
                seen += 1
        except (struct.error, OSError):
            pass

    def _rva_to_offset_naive(
        self, data: bytes, rva: int, info: Optional[PEInfo]
    ) -> Optional[int]:
        """Convert RVA to file offset using the section table."""
        if info is not None:
            for section in info.sections:
                if section.virtual_address <= rva < section.virtual_address + max(
                    section.virtual_size, section.raw_size
                ):
                    return section.raw_pointer + (rva - section.virtual_address)
        # Header-space RVAs (before the first section) map 1:1.
        if info is not None and info.sections:
            first = min(s.virtual_address for s in info.sections)
            if rva < first:
                return rva
        if rva < len(data):
            return rva
        return None

    def _has_version_resource(self, data: bytes, resource_rva: int, info: Optional[PEInfo]) -> bool:
        """Search for the 'VS_VERSION_INFO' marker near the resource dir."""
        try:
            offset = self._rva_to_offset_naive(data, resource_rva, info)
            if offset is None:
                return False
            window = data[offset:offset + 65536]
            return b"V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00" in window
        except (OSError, struct.error):
            return False


def summarize_pe_info(info: PEInfo) -> str:
    """One-paragraph PE summary for the UI technical details view."""
    if not info.is_pe:
        return "Not a PE executable."
    lines = [
        f"Architecture: {info.architecture or 'unknown'}",
        f"Sections: {len(info.sections)}",
        f"Imports (DLLs): {len(info.imports)}",
        f"Digital signature: {'present' if info.has_digital_signature else 'none'}",
        f"Version info: {'present' if info.has_version_info else 'none'}",
    ]
    if info.error:
        lines.append(f"Note: {info.error}")
    return "\n".join(lines)

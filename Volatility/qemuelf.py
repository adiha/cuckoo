# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# phil@teuwen.org (Philippe Teuwen)
# justincapella@gmail.com (Justin Capella)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# References:


import volatility.obj as obj
import volatility.addrspace as addrspace
from volatility.plugins.filescan import PSScan
import volatility.plugins.addrspaces.standard as standard

#pylint: disable-msg=C0111

NT_QEMUCORE = 0x1


class QemuCoreDumpElf(addrspace.AbstractRunBasedMemory):
    """ This AS supports Qemu ELF coredump format """

    order = 30
    # ADI
    dtb = 3063808

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

        ## for ELF32, little-endian - ELFCLASS32 and ELFDATA2LSB
        if base.read(0, 6) == '\x7fELF\x01\x01':
            hdr_type = "elf32_hdr"
            note_type = "elf32_note"
        ## for ELF64, little-endian - ELFCLASS64 and ELFDATA2LSB
        elif base.read(0, 6) == '\x7fELF\x02\x01':
            hdr_type = "elf64_hdr"
            note_type = "elf64_note"
        else:

            self.as_assert(base.read(0, 4) == '\x7fELF',
                           "ELF Header signature invalid")

        ## Base AS should be a file AS
        elf = obj.Object(hdr_type, offset=0, vm=base)

        ## Make sure its a core dump
        self.as_assert(str(elf.e_type) == 'ET_CORE',
                       "ELF type is not a Core file")
        ## Tuple of (physical memory address, file offset, length)
        self.runs = []

        ## The PT_NOTE core descriptor structure
        self.header = None

        success = False
        for phdr in elf.program_headers():
            ## The first note should be the CORE segment
            if str(phdr.p_type) == 'PT_NOTE':
                note = phdr.p_offset.dereference_as(note_type)
                if str(note.namesz) == 'CORE' and note.n_type == NT_QEMUCORE:
                    success = True
                continue

            # Only keep load segments with valid file sizes
            if (str(phdr.p_type) != 'PT_LOAD' or
                    phdr.p_filesz == 0 or
                    phdr.p_filesz != phdr.p_memsz):
                continue

            self.runs.append((int(phdr.p_paddr),
                              int(phdr.p_offset),
                              int(phdr.p_memsz)))

        self.as_assert(success, 'ELF error: did not find any PT_NOTE segment with CORE')
        self.as_assert(self.runs, 'ELF error: did not find any LOAD segment with main RAM')

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        for run in self.runs:
            yield (run[0], run[2])

    def write(self, phys_addr, buf):
        """This is mostly for support of raw2dmp so that 
        it can modify the kernel CONTEXT after the crash
        dump has been written to disk"""

        if not self._config.WRITE:
            return False

        file_addr = self.translate(phys_addr)

        if file_addr is None:
            return False
	
        return self.base.write(file_addr, buf), file_addr


    def is_valid_address(self, vaddr):
        """Returns whether a virtual address is valid"""
	"""import pdb;pdb.set_trace()
        if vaddr == None or vaddr < 0:
            return False
        try:
            paddr = self.vtop(vaddr)
        except BaseException:
            return False
        if paddr == None:
            return False"""
        return self.base.is_valid_address(vaddr)



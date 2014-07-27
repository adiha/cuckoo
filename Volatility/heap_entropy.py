# done by Marko Thure

import math
import array

import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.plugins.taskmods as taskmods
import volatility.plugins.heap


HEAP_ENTRY_FLAGS = dict(
    HEAP_ENTRY_BUSY           = 0x01,
    HEAP_ENTRY_EXTRA_PRESENT  = 0x02,
    HEAP_ENTRY_FILL_PATTERN   = 0x04,
    HEAP_ENTRY_VIRTUAL_ALLOC  = 0x08,
    HEAP_ENTRY_LAST_ENTRY     = 0x10,
    HEAP_ENTRY_SETTABLE_FLAG1 = 0x20,
    HEAP_ENTRY_SETTABLE_FLAG2 = 0x40,
    HEAP_ENTRY_SETTABLE_FLAG3 = 0x80,
)

HEAP_SEGMENT_FLAGS = dict(
    HEAP_USER_ALLOCATED  =  0x1
)

HEAP_FLAGS = dict(
    HEAP_NO_SERIALIZE             = 0x00000001L,
    HEAP_GROWABLE                 = 0x00000002L,
    HEAP_GENERATE_EXCEPTIONS      = 0x00000004L,
    HEAP_ZERO_MEMORY              = 0x00000008L,
    HEAP_REALLOC_IN_PLACE_ONLY    = 0x00000010L,
    HEAP_TAIL_CHECKING_ENABLED    = 0x00000020L,
    HEAP_FREE_CHECKING_ENABLED    = 0x00000040L,
    HEAP_DISABLE_COALESCE_ON_FREE = 0x00000080L,
    HEAP_CREATE_ALIGN_16          = 0x00010000L,
    HEAP_CREATE_ENABLE_TRACING    = 0x00020000L,
    HEAP_CREATE_ENABLE_EXECUTE    = 0x00040000L,
)


def entropy_H(data):
        """Calculate the entropy of a chunk of data."""

        if len(data) == 0:
            return 0.0

        occurences = array.array('L', [0]*256)

        for x in data:
            occurences[ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy


class HeapEntropy(taskmods.DllList):

    def __init__(self, config, *args):
       taskmods.DllList.__init__(self, config, *args)
        
    def calculate(self, wanted_pid=None):
	if wanted_pid is not None:
		self._config.PID = wanted_pid
	
	heapscan = volatility.plugins.heap.HeapScan(self._config).calculate()
	heaps = {}
        for pid, procname, heap, heap_segments, heap_freelists, heap_virt_blocks in heapscan:


            for segment in heap_segments:

                entry_offs = segment.FirstEntry.v()
                HeapFlags = heap.Flags.v()

                while 1:

                    entry = obj.Object('_HEAP_ENTRY',offset = entry_offs, vm = heap.obj_vm)

                    if not entry:
                        break
                    if entry.Size == 0:
                        break

                    block_size = (entry.Size-1) * 8
                    block_data = entry.obj_vm.zread(entry.v()+8,block_size)
                    entry_offs += block_size + 8

                    entry_flags = self.get_flags(HEAP_ENTRY_FLAGS,entry.Flags.v())
                    heap_flags = self.get_flags(HEAP_FLAGS,HeapFlags)

                    if heaps.has_key(pid):
                        heaps[pid] += block_data
                    else:
                        heaps[pid] = block_data

                    if 'HEAP_ENTRY_FLAGS_LAST_ENTRY' in entry_flags:
                        break
            
        for proc in heaps.keys():
                entropy = entropy_H(heaps[proc])
                yield proc, entropy

    def render_text(self, outfd, data):
	outfd.write("{0:<4} {1:<18}\n".format("Pid", "Entropy"))
        outfd.write("------------------------\n")
        for proc, entropy in data:
		outfd.write("\n{0:<4} {1:<18}\n".format(proc, entropy))


    def get_flags(self, flags, val):

        if flags.has_key(val):
            return flags[val]
        else:
            return [f for f in flags if (flags[f] | val == val)]


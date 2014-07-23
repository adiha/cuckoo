//
// Reference Lister
//
// List all functions and all references to them in the current section.
//
// Implemented in IDC
//
#include <idc.idc>


static get_disasm_blob(f, func_start, func_end) 
{
	auto curAddr, endAddr;
	curAddr = func_start;
	endAddr = func_end;
	
	while ((curAddr <= endAddr) && (curAddr != 0xffffffff)) {
		fprintf(f, GetDisasm(curAddr));
		fprintf(f, "\n");
		curAddr = NextHead(curAddr, endAddr);
		
	}

}
static FuncDump(start)
{
    auto ea, str, count, ref, x, i, f;
    auto end;
    auto teststr;
	f = fopen("/tmp/functions", "a+");
    ea = start;

    while( ea != BADADDR )
    {
        str = GetFunctionName(ea);
        if( str != 0 )
        {
            end = FindFuncEnd(ea);

            count = 0;
            ref = RfirstB(ea);
            while(ref != BADADDR)
            {
                count = count + 1;
                ref = RnextB(ea, ref);
            }

            teststr = form("sub_%X", ea);
            if( teststr == str )
            {
				//fprintf(f, "-s 0x%X=%s\n", ea, str );
				
                
				fprintf(f, "%s^", str);
				// fprintf(f, form("%s,", GetDisasm(ea)) );
				
				for ( i=ea; i < end; i=i+1 ) { 
					x = Byte(i);    // fetch the byte
					//Message(x);
					fprintf(f, form("%x",x));
				  } 
				  
				fprintf(f, "^");
				//Message(form("%d", end));
				get_disasm_blob(f, ea, end);
				fprintf(f, "--------------\n");
				
				//Message("%s, 0x%d, 0x%x, 0x%x, 0x%x, %d, 0x%x\n", str, count, ea, end, end-ea, end-ea, x   );
            }
            
        }

        ea = NextFunction(ea);
    }
	
	
}

static main() 
{
    auto ea, func, ref;
	Wait();
	//Message("FuncDump: Start\n");

	
    FuncDump(0x40000);
	
	//Message("FuncDump: Done\n");
    

    // Get current ea
    //ea = ScreenEA();

    // Loop from start to end in the current segment
    /*for (func=SegStart(ea); 
    func != BADADDR && func < SegEnd(ea); 
    func=NextFunction(func)) 
        {
                // If the current address is function process it
                if (GetFunctionFlags(func) != -1)
                {
                        //Message("Function %s at 0x%x\n", GetFunctionName(func), func);

                        // Find all code references to func
                        for (ref=RfirstB(func); ref != BADADDR; ref=RnextB(func, ref))
                        {
                                //Message("  called from %s(0x%x)\n", GetFunctionName(ref), ref);
                        }

                }
        }
	*/
}
	




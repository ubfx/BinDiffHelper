package bindiffhelper;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;

import com.google.security.zynamics.BinExport.BinExport2;
import com.google.security.zynamics.BinExport.BinExport2.CallGraph;
import com.google.security.zynamics.BinExport.BinExport2.CallGraph.Vertex;

import ghidra.program.model.address.Address;

public class BinExport2File {

	protected BinExport2 be;
	protected HashMap<Long, String> functionNames;
	
	public BinExport2File(File f) throws Exception
	{
		FileInputStream fi = new FileInputStream(f);
		be = BinExport2.parseFrom(fi);
		fi.close();
		
		functionNames = new HashMap<Long, String>();
		CallGraph cg = be.getCallGraph();
		for (Vertex v : cg.getVertexList())
		{
			functionNames.put(v.getAddress(), v.getMangledName());
		}
	}
	
	public boolean hasFunctionName(long address)
	{
		return functionNames.containsKey(address);
	}
	
	public String getFunctionName(Address address)
	{		
		return getFunctionName(address.getUnsignedOffset());
	}
	
	public String getFunctionName(long address)
	{		
		return functionNames.get(address);
	}
}

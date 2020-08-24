package bindiffhelper;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

public class ComparisonTableModel extends AbstractTableModel {
    private String[] columnNames = {
    		"Import",
    		"Address this file",
    		"Name this file",
    		"Name Database",
    		"Address other file",
    		"Name other file",
    		"Similarity",
    		"Confidence",
    		"Algorithm"
    };
    
    private List<Entry> data;
    

    public ComparisonTableModel() {
    	data = new ArrayList<Entry>();
    }
    
    public void addEntry(Entry e) {
    	data.add(e);
    }
    
    public List<Entry> getEntries() {
    	return data;
    }
    
    public int getColumnCount() {
        return columnNames.length;
    }

    public int getRowCount() {
        return data.size();
    }

    public String getColumnName(int col) {
        return columnNames[col];
    }

    public Object getValueAt(int row, int col) {
    	Entry e = data.get(row);
    	
    	switch (col) {
    	case 0:
    		return e.do_import;
    	case 1:
    		if(e.primaryAddress != null)
    			return "0x" + Long.toHexString(e.primaryAddress.getUnsignedOffset());
    		return "";
    	case 2:
    		if (e.primaryFunctionSymbol != null)
    			return e.primaryFunctionSymbol.getName();
    		return "No Symbol";
    	case 3:
    		if(e.primaryFunctionNameDb != null)
    			return e.primaryFunctionNameDb;
    		return "";
    	case 4:
    		return "0x" + Long.toHexString(e.secondaryAddress);
    	case 5:
    		if(e.secondaryFunctionName != null)
    			return e.secondaryFunctionName;
    		return "";
    	case 6:
    		return e.similarity;    	
    	case 7:
    		return e.confidence;    	
    	case 8:
    		return e.algorithm;
    	}
    	
    	return null;
    }

	@Override
	public boolean isCellEditable(int row, int col)
	{
		if (col == 0)
			return true;
		return false;
	}

    public Class<?> getColumnClass(int c) {
    	if (c == 0)
    		return Boolean.class;
    	//else if (c == 5)
    	//	return Double.class;
    	
    	return String.class;
    }

    public void setValueAt(Object value, int row, int col) {
    	if (col != 0)
    		return;
    	
        data.get(row).do_import = (boolean)value;
        
        fireTableCellUpdated(row, col);
    }
    
    public Entry getEntry(int row)
    {
    	return data.get(row);
    }
    
    public static class Entry {
    	boolean do_import;
    	final Address primaryAddress;
    	final String primaryFunctionNameDb;
    	final Symbol primaryFunctionSymbol;
    	final long secondaryAddress;
    	final String secondaryFunctionName;
    	final double similarity;
    	final double confidence;
    	final String algorithm;
    	
    	public Entry(boolean i, Address pa, String pfn, Symbol pfs, long sa, String sfn, double sim, double con, String alg)
    	{
    		do_import = i;
    		primaryAddress = pa;
    		primaryFunctionNameDb = pfn;
    		primaryFunctionSymbol = pfs;
    		secondaryAddress = sa;
    		secondaryFunctionName = sfn;
    		similarity = sim;
    		confidence = con;
    		algorithm = alg;
    	}
    	
    	public boolean symbolRenamed()
    	{
    		if (primaryFunctionSymbol == null)
    			return true;
    		
    		return !primaryFunctionNameDb.equals(primaryFunctionSymbol.getName());
    	}
    }
}

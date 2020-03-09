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
    		"Address other file",
    		"Name other file",
    		"Similarity"
    };
    
    private List<Entry> data;
    

    public ComparisonTableModel()
    {
    	data = new ArrayList<Entry>();
    }
    
    public void addEntry(Entry e)
    {
    	data.add(e);
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
    		return "0x" + Long.toHexString(e.primaryAddress.getUnsignedOffset());
    	case 2:
    		if (e.symbolRenamed())
    			return "DB: " + e.primaryFunctionName + " / opened: " + e.primaryFunctionSymbol.getName();
    		
    		return e.primaryFunctionName;
    	case 3:
    		return "0x" + Long.toHexString(e.secondaryAddress);
    	case 4:
    		return e.secondaryFunctionName;
    	case 5:
    		return e.similarity;    			
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
    	
    	return String.class;
    }

    public void setValueAt(Object value, int row, int col) {
    	if (col != 0)
    		return;
    	
        data.get(row).do_import = (boolean)value;
        
        fireTableCellUpdated(row, col);
    }
    
    public static class Entry {
    	boolean do_import;
    	Address primaryAddress;
    	String primaryFunctionName;
    	Symbol primaryFunctionSymbol;
    	long secondaryAddress;
    	String secondaryFunctionName;
    	double similarity;
    	
    	public Entry(boolean i, Address pa, String pfn, Symbol pfs, long sa, String sfn, double sim)
    	{
    		do_import = i;
    		primaryAddress = pa;
    		primaryFunctionName = pfn;
    		primaryFunctionSymbol = pfs;
    		secondaryAddress = sa;
    		secondaryFunctionName = sfn;
    		similarity = sim;
    	}
    	
    	public boolean symbolRenamed()
    	{
    		return !primaryFunctionName.equals(primaryFunctionSymbol.getName());
    	}
    }
}
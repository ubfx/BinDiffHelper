/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bindiffhelper;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import resources.ResourceManager;

public class BinDiffHelperProvider extends ComponentProviderAdapter {

	protected BinDiffHelperPlugin plugin;
	
	protected JPanel gui;
	protected GTable table;
	ComparisonTableModel ctm;
	
	protected JScrollPane scrollPane;
	
	protected Connection conn;
	protected Program program;
	
	protected ImportFunctionNamesAction fna;
	protected FlatProgramAPI api;
	
	protected CodeViewerService cvs;
	
	public BinDiffHelperProvider(BinDiffHelperPlugin plugin, Program program) {
		super(plugin.getTool(), "BinDiffHelper GUI Provider", plugin.getName());
		
		this.plugin = plugin;
		setProgram(program);
		
		setIcon(ResourceManager.loadImage("images/BDH.png"));
		
		gui = new JPanel(new BorderLayout());
	
		gui.setFocusable(true);
		gui.setMinimumSize(new Dimension(400, 400));
		gui.setPreferredSize(new Dimension(1400, 850));
		
		setDefaultWindowPosition(WindowPosition.WINDOW);
		
		createActions();
	}
	
	public void refresh()
	{
		gui.revalidate();
		gui.repaint();
	}
	
	private void createActions()
	{
		OpenFromBDFileAction odb = new OpenFromBDFileAction(plugin);
		OpenFromProjectAction op = new OpenFromProjectAction(plugin);
		
		op.setEnabled(false);
		fna = new ImportFunctionNamesAction(plugin);
		fna.setEnabled(false);
		
		addLocalAction(odb);
		addLocalAction(op);
		
		addLocalAction(fna);
		
	}
	
	void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return gui;
	}
	
	public void execute(Command c)
	{
		if (program == null)
			return;
		
		tool.execute(c, program);
	}
	
	public void setProgram(Program p)
	{
		program = p;
		if (p != null) {
			api = new FlatProgramAPI(program);
			cvs = plugin.getTool().getService(CodeViewerService.class);
		}
	}
	
	protected boolean isBinDiff6(Connection c) throws Exception
	{
		boolean ret = true;
		
		Statement stmt = conn.createStatement();
		ResultSet rs = stmt.executeQuery("SELECT version from metadata");
		
		if (!rs.getString(1).startsWith("BinDiff 6")) {
			ret = false;
		}
		
		stmt.close();
		
		return ret;
	}
	
	protected String[][] getBinDiffFilenames(Connection conn) throws Exception
	{
		String[][] ret = new String[2][2];
		
		Statement stmt = conn.createStatement();
		
		ResultSet rs = stmt.executeQuery("SELECT filename, exefilename FROM file");
		
		int i = 0;
		while (rs.next())
		{
			ret[i][0] = rs.getString("filename");
			ret[i++][1] = rs.getString("exefilename");
		}
		
		stmt.close();
		
		return ret;
	}
	
	protected void openBinDiffDB(String filename) {
		
		if (program == null)
		{
			return;
		}
			
		if (!filename.endsWith(".BinDiff"))
		{
			Msg.showInfo(this, getComponent(), "Info", "Unexpected filename ending (expected .BinDiff)");
		}
		
		String pname = program.getName().toString();
		
		
		try {
			conn = DriverManager.getConnection("jdbc:sqlite:" + filename);
			
			if (!isBinDiff6(conn)) {
				Msg.showError(this, this.getComponent(), "Error", "Can't open this file as a BinDiff 6 file");
				
				return;
			}
			
			String[][] filenames = getBinDiffFilenames(conn);
			Path bindiff = Paths.get(filename);
			int loadedProgramIndex = -1;
			
			BinExport2File[] bi = new BinExport2File[2];
			for (int i = 0; i < 2; i++)
			{
				File binExportFile = bindiff.resolveSibling(filenames[i][0] + ".BinExport").toFile();
				
				if (!binExportFile.exists())
				{
					Msg.showError(this, getComponent(), "Error", "Could not open " + binExportFile.getAbsolutePath());
					return;
				}
				
				if (pname.equals(filenames[i][1]))
				{
					loadedProgramIndex = i;
				
					bi[0] = new BinExport2File(binExportFile);
				}
				else
					bi[1] = new BinExport2File(binExportFile);
			}
			
			if (loadedProgramIndex == -1)
			{
				Msg.showError(this, getComponent(), "Error",
						"Could not find loaded Program in BinDiff files\n" + pname + "\nin\n" +
						filenames[0][0] + "\n" + filenames[0][0]);
				
				return;
			}
			
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery("SELECT address1, address2, similarity, name FROM function JOIN functionalgorithm ON function.algorithm=functionalgorithm.id ORDER BY similarity DESC");
			
			String priAddressCol, secAddressCol;
			if (loadedProgramIndex == 0)
			{
				priAddressCol = "address1";
				secAddressCol = "address2";
			}
			else
			{
				priAddressCol = "address2";
				secAddressCol = "address1";
			}
			
			AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
			
			
			ctm = new ComparisonTableModel();
			
			while (rs.next())
			{
				Address priAddress = addrSpace.getAddress(rs.getLong(priAddressCol));
				long secAddress = rs.getLong(secAddressCol);

				double similarity = rs.getDouble("similarity");
				
				Symbol s = api.getSymbolAt(priAddress);
				
				String priFn = bi[0].getFunctionName(priAddress);
				String secFn = bi[1].getFunctionName(secAddress);
				
				boolean defaultTicked = similarity == 1.0f && !secFn.startsWith("thunk_FUN_") && !secFn.startsWith("FUN_") && !priFn.equals(secFn);
				ctm.addEntry(
						new ComparisonTableModel.Entry(defaultTicked,
								priAddress,
								priFn,
								s,
								secAddress,
								secFn,
								similarity,
								rs.getString("name"))
				);
			}
			stmt.close();
			
			Msg.showInfo(this, this.getComponent(), "Success", "Opened successfully");
			
			boolean createTable = table == null;
			
			if (createTable)
			{
				table = new GTable();
				scrollPane = new JScrollPane(table);
				gui.removeAll();
				gui.add(scrollPane, BorderLayout.CENTER);
			}
			
			table.setModel(ctm);
			
			table.getColumn("Import").setMaxWidth(50);
			table.setAutoResizeMode(GTable.AUTO_RESIZE_ALL_COLUMNS);
			
			table.addMouseListener(new MouseAdapter() {
				public void mousePressed(MouseEvent e) {
					if (e.getClickCount() == 2 && table.getSelectedRow() != -1)
					{
						var entry = ctm.getEntry(table.getSelectedRow());
						cvs.goTo(new ProgramLocation(program, entry.primaryAddress), true);
					}
				}
			});
			
			fna.setEntries(ctm.getEntries());
			fna.setEnabled(true);
			
			gui.revalidate();
			gui.repaint();
		} catch (Exception e) {
			Msg.showError(this, this.getComponent(), "Error: ", e.toString());
			return;
		}		
	}
	
	public class OpenFromBDFileAction extends DockingAction implements OpenDialog.Caller {

		BinDiffHelperPlugin plugin;
		
		public OpenFromBDFileAction(BinDiffHelperPlugin plugin) {
			super("Open from BinDiffFile", plugin.getName());
			
			this.setMenuBarData(new MenuData(new String[] { "Open", "From BinDiffFile" }, "Open"));
			
			setToolBarData(new ToolBarData(ResourceManager.loadImage("images/open_db.png"), ""));

			setDescription(HTMLUtilities.toHTML("Open from BinDiff output file"));
			
			this.plugin = plugin;
			
		}
	
		@Override
		public void actionPerformed(ActionContext context) {
			OpenDialog d = new OpenDialog(this, "Open BinDiff 6 file", "de.ubfx.bindiffhelper.bindiffinputfile",
					"Select the File created with BinDiff 6 (usually ends in .BinDiff)");
			DockingWindowManager.showDialog(d, plugin.provider.getComponent());
		}

		@Override
		public void importDialogFileSelected(String filename) {
			openBinDiffDB(filename);
		}
		
	}
	
	public class OpenFromProjectAction extends DockingAction implements OpenDialog.Caller {

		public OpenFromProjectAction(BinDiffHelperPlugin plugin) {
			super("Open from Project", plugin.getName());
			
			this.setMenuBarData(new MenuData(new String[] { "Open", "From Project" }, "Open"));
			
			setToolBarData(new ToolBarData(ResourceManager.loadImage("images/open_from_project.png"), ""));

			setDescription(HTMLUtilities.toHTML("Open from Project"));
			
		}

		@Override
		public void actionPerformed(ActionContext context) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void importDialogFileSelected(String filename) {
			// TODO Auto-generated method stub
			
		}
		
	}
}

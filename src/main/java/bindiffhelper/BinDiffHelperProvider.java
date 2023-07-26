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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ComponentProviderAdapter;
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
	
	protected ImportCheckedFunctionNamesAction importCheckedAction;
	protected ImportAllFunctionNamesAction importAllAction;
	protected UpdatePlateCommentsAction upca;
	protected UpdateFunctionColoringAction ufca;
	
	protected CodeViewerService cvs;
	
	protected final boolean hasExporter;
	
	protected String thisProg, otherProg;
	
	public BinDiffHelperProvider(BinDiffHelperPlugin plugin, Program program) {
		super(plugin.getTool(), "BinDiffHelper GUI Provider", plugin.getName());
		
		hasExporter = plugin.binExportExporter != null;
		
		this.plugin = plugin;
		setProgram(program);
		
		setIcon(ResourceManager.loadImage("images/BDH.png"));
		
		gui = new JPanel(new BorderLayout());
	
		generateWarnings();
		
		setDefaultWindowPosition(WindowPosition.WINDOW);
		gui.setFocusable(true);
		gui.setMinimumSize(new Dimension(400, 400));
		gui.setPreferredSize(new Dimension(1200, 425));
		
		createActions();
	}
	
	public void generateWarnings()
	{
		if (table != null)
			return;
		
		gui.removeAll();
		
		List<String> warnings = new ArrayList<String>();
		
		if (!hasExporter) {
			warnings.add("The BinExport plugin couldn't be found so some features are disabled.<br />" +
					"See the Readme at https://github.com/ubfx/BinDiffHelper for a link " +
					"to the BinExport as binaries or in source.");
		}
		
		if (plugin.binDiffBinary == null) {
			warnings.add("BinDiff binary has not been set so some features are disabled.<br />" +
					"Go to the settings button and select the BinDiff binary if you want to connect with BinDiff directly<br />" +
					"You can download BinDiff from https://zynamics.com/software.html");
		}
		
		if (!warnings.isEmpty()) {
			String labelContent = "<html>";
			
			for (String w : warnings)
				labelContent += "<p>" + w + "</p><br />";
			
			labelContent += "</html>";
			JLabel warningLabel = new JLabel(labelContent, SwingConstants.CENTER);
			gui.add(warningLabel, BorderLayout.CENTER);
		}
		
		refresh();
	}
	
	public void refresh()
	{
		gui.revalidate();
		gui.repaint();
	}
	
	private void createActions()
	{
		GeneralOpenAction op = new GeneralOpenAction(plugin);
		SettingsDialogAction sa = new SettingsDialogAction(plugin);
		
		addLocalAction(sa);
		
		importCheckedAction = new ImportCheckedFunctionNamesAction(plugin);
		importCheckedAction.setEnabled(false);
		importAllAction = new ImportAllFunctionNamesAction(plugin);
		importAllAction.setEnabled(false);
		upca = new UpdatePlateCommentsAction(plugin);
		upca.setEnabled(false);
		ufca = new UpdateFunctionColoringAction(plugin);
		ufca.setEnabled(false);

		addLocalAction(op);
		addLocalAction(importCheckedAction);
		addLocalAction(importAllAction);
		addLocalAction(upca);
		addLocalAction(ufca);
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
			cvs = plugin.getTool().getService(CodeViewerService.class);
		}
	}
	
	protected boolean isBinDiff6or7(Connection c) throws Exception
	{
		boolean ret = true;
		
		Statement stmt = conn.createStatement();
		ResultSet rs = stmt.executeQuery("SELECT version from metadata");
		
		if (!rs.getString(1).startsWith("BinDiff 6") && !rs.getString(1).startsWith("BinDiff 7")) {
			ret = false;
		}
		
		stmt.close();
		
		return ret;
	}

	protected BinDiffFileDescriptor[] getBinDiffFileDescriptors(Connection conn) throws Exception
	{
		BinDiffFileDescriptor[] ret = new BinDiffFileDescriptor[2];
		
		Statement stmt = conn.createStatement();
		
		ResultSet rs = stmt.executeQuery("SELECT filename, exefilename, hash FROM file");
		
		for (int i = 0; i < 2; i++) {
			if (!rs.next())
				throw new Exception("");
			
			ret[i] = new BinDiffFileDescriptor(rs.getString("filename"),
					rs.getString("exefilename"),
					rs.getString("hash"));
		}
		
		stmt.close();
		
		return ret;
	}
	
	protected void openBinDiffDB(String filename)
	{
		openBinDiffDB(filename, null, null);
	}
	
	protected void openBinDiffDB(String filename, File be0, File be1) {
		
		if (program == null)
		{
			return;
		}
		
		if (!filename.endsWith(".BinDiff"))
		{
			Msg.showInfo(this, getComponent(), "Info", "Unexpected filename ending (expected .BinDiff)");
		}
		
		try {
			String pname = program.getDomainFile().getName().toString();
			
			BinExport2File[] bi = new BinExport2File[2];
			
			conn = DriverManager.getConnection("jdbc:sqlite:" + filename);
			
			if (!isBinDiff6or7(conn)) {
				Msg.showError(this, this.getComponent(), "Error", "Can't open this file as a BinDiff 6/7 file");
				
				return;
			}
			
			int loadedProgramIndex = -1;
			
			if (be0 == null || be1 == null)
			{				
				BinDiffFileDescriptor[] fds = getBinDiffFileDescriptors(conn);
				
				Path bindiff = Paths.get(filename);
				
				for (int i = 0; i < 2; i++)
				{
					File binExportFile = bindiff.resolveSibling(fds[i].getFilename() + ".BinExport").toFile();
					
					if (!binExportFile.exists())
					{
						Msg.showError(this, getComponent(), "Error", "Could not open " + binExportFile.getAbsolutePath());
						return;
					}
					
					bi[i] = new BinExport2File(binExportFile);
				}
				
				MatchDialog md = new MatchDialog(program, fds);
				tool.showDialog(md);
				
				loadedProgramIndex = md.getSelected();
				if (loadedProgramIndex == -1)
				{
					Msg.showError(this, getComponent(), "Error",
							"Could not find loaded Program in BinDiff files\n" + pname + "\nin\n" +
							fds[0].getFilename() + "\n" + fds[1].getFilename());
					
					return;
				} else if (loadedProgramIndex == 1) {
					// TODO: fix this
					BinExport2File temp = bi[0];
					bi[0] = bi[1];
					bi[1] = temp;
					
					thisProg = fds[1].getFilename();
					otherProg = fds[0].getFilename();
				} else {
					thisProg = fds[0].getFilename();
					otherProg = fds[1].getFilename();
				}
				
				
			}
			else
			{
				loadedProgramIndex = 0;
				bi[0] = new BinExport2File(be0);
				bi[1] = new BinExport2File(be1);
			}
			
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery( "SELECT address1, address2, similarity, confidence, name "
					+ "FROM function JOIN functionalgorithm ON function.algorithm=functionalgorithm.id "
					+ "ORDER BY similarity DESC"
					);
			
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
			
			Set<Long> priFnSet = bi[0].getFunctionAddressSet();
			Set<Long> commonPriFnSet = new TreeSet<Long>();
			Set<Long> secFnSet = bi[1].getFunctionAddressSet();
			Set<Long> commonSecFnSet = new TreeSet<Long>();

			
			ctm = new ComparisonTableModel();
			var st = program.getSymbolTable();
			
			while (rs.next())
			{

				Address priAddress = addrSpace.getAddress(rs.getLong(priAddressCol));
				long secAddress = rs.getLong(secAddressCol);
				
				// Store the addresses of functions that are the same so we can add sets of functions that are in one but not the other
				commonPriFnSet.add(rs.getLong(priAddressCol));
				commonSecFnSet.add(rs.getLong(secAddressCol));

				Symbol s = null;
				
				if (st.hasSymbol(priAddress))
					s = st.getSymbols(priAddress)[0];
				
				String priFn = bi[0].getFunctionName(priAddress);
				String secFn = bi[1].getFunctionName(secAddress);
				
				double similarity = rs.getDouble("similarity");
				double confidence = rs.getDouble("confidence");
				
				// TODO: Document this: Note to self, this assumes that the DB that has had the work done to it is the secondary. 
				// IE we are looking at a new file and we've done a bindiff against a DB where we've already done some RE work.
				// We may want to add toggle here so if you are trying to look at a "new" db as the secondary file we do the right thing.
				boolean defaultTicked = similarity == 1.0f && !secFn.startsWith("thunk_FUN_") && !secFn.startsWith("FUN_") && !priFn.equals(secFn);
				ctm.addEntry(
						new ComparisonTableModel.Entry(defaultTicked,
								priAddress,
								priFn,
								s,
								secAddress,
								secFn,
								similarity,
								confidence,
								rs.getString("name"))
				);
			}
			stmt.close();
			
			// Now lets add functions that are in our program but not the other to the list
			Set<Long> onlyInPrimary = new TreeSet<Long>(priFnSet);
			onlyInPrimary.removeAll(commonPriFnSet);
			Set<Long> onlyInSecondary = new TreeSet<Long>(secFnSet);
			onlyInSecondary.removeAll(commonSecFnSet);
			// Lets add the functions that are only in the primary here
			for(Long x : onlyInPrimary) {
				Address priAddress = addrSpace.getAddress(x);
				Symbol s = null;
				String priFn = bi[0].getFunctionName(priAddress);
				if(st.hasSymbol(priAddress))
					s = st.getSymbols(priAddress)[0];
				ctm.addEntry(
						new ComparisonTableModel.Entry(false, priAddress, priFn, s, 0, null, 0, 1, "Only in primary")
						);
			}
			// Lets add the functions that are only in the secondary here
			for(Long x : onlyInSecondary) {
				String secFn = bi[1].getFunctionName(x);
				ctm.addEntry(
						new ComparisonTableModel.Entry(false, null, null, null, x, secFn, 0, 1, "Only in Secondary")
						);
			}
			
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
			table.getColumn("Similarity").setMaxWidth(100);
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
			
			importCheckedAction.setEntries(ctm.getEntries());
			importCheckedAction.setEnabled(true);
			importAllAction.setEntries(ctm.getEntries());
			importAllAction.setEnabled(true);
			upca.setEntries(ctm.getEntries());
			upca.setEnabled(true);
			ufca.setEntries(ctm.getEntries());
			ufca.setEnabled(true);
			
			refresh();
		} catch (Exception e) {
			Msg.showError(this, this.getComponent(), "Error: ", e.toString());
			return;
		}		
	}
	
	public class GeneralOpenAction extends DockingAction {

		public GeneralOpenAction(BinDiffHelperPlugin plugin) {
			super("Open from Project", plugin.getName());
			
			this.setMenuBarData(new MenuData(new String[] { "Open", "Open a file for comparison" }, "Open"));
			
			setToolBarData(new ToolBarData(ResourceManager.loadImage("images/open_from_project.png"), "Open"));

			setDescription(HTMLUtilities.toHTML("Open a file for comparison"));
			
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DockingWindowManager.showDialog(new GeneralOpenDialog(plugin));
		}		
	}
	
	public class SettingsDialogAction extends DockingAction {

		private BinDiffHelperPlugin plugin;
		
		public SettingsDialogAction(BinDiffHelperPlugin plugin) {
			super("Settings", plugin.getName());
		
			this.plugin = plugin;
			
			this.setMenuBarData(new MenuData(new String[] { "Settings" }, "Settings"));
			
			setToolBarData(new ToolBarData(ResourceManager.loadImage("images/setting_tools.png"), "Settings"));

			setDescription(HTMLUtilities.toHTML("Settings"));
			
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DockingWindowManager.showDialog(new SettingsDialog(plugin));
		}	
	}
	
	public class BinDiffFileDescriptor {
		private String filename, exefilename, hash;
		
		public BinDiffFileDescriptor(String filename, String exefilename, String hash)
		{
			this.filename = filename;
			this.exefilename = exefilename;
			this.hash = hash;
		}
		
		public String getFilename() {
			return filename;
		}
		
		public String getExeFilename() {
			return exefilename;
		}
		
		public String getHash() {
			return hash;
		}
	}
}

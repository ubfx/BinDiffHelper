package bindiffhelper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import resources.ResourceManager;

class ImportFunctionNamesAction extends DockingAction {

	protected BinDiffHelperPlugin plugin;

	List<ComparisonTableModel.Entry> entries;

	public ImportFunctionNamesAction(String name, BinDiffHelperPlugin plugin) {
		super(name, plugin.getName());
		this.plugin = plugin;
	}

	public void setEntries(List<ComparisonTableModel.Entry> e) {
		entries = e;
	}

	protected boolean shouldImportEntry(ComparisonTableModel.Entry e) {
		return false;
	}

	private Namespace getOrCreateNamespace(Program program, String namespacePath) throws Exception {

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace currentNamespace = program.getGlobalNamespace();

		if (namespacePath == null || namespacePath.isEmpty()) {
			return currentNamespace;
		}

		String[] namespaces = namespacePath.split("::");
		for (String namespaceName : namespaces) {
			ghidra.program.model.symbol.Namespace nextNamespace = symbolTable.getNamespace(
					namespaceName, currentNamespace);

			if (nextNamespace == null) {
				nextNamespace = symbolTable.createNameSpace(
						currentNamespace, namespaceName, SourceType.IMPORTED);
			}

			currentNamespace = nextNamespace;
		}

		return currentNamespace;
	}

	@Override
	public void actionPerformed(ActionContext arg0) {
		int trans = plugin.program.startTransaction("Rename functions");

		Map<String, Exception> changes = new HashMap<String, Exception>();

		for (var e : entries) {
			if (!shouldImportEntry(e))
				continue;

			String transformation = "(none)";
			Exception exp = null;
			try {
				transformation = e.primaryFunctionSymbol.getName() + " -> " + e.secondaryFunctionName;

				if (e.secondaryFunctionName.contains("::")) {
					String[] parts = e.secondaryFunctionName.split("::");
					String methodName = parts[parts.length - 1];

					StringBuilder namespacePath = new StringBuilder();
					for (int i = 0; i < parts.length - 1; i++) {
						if (i > 0) namespacePath.append("::");
						namespacePath.append(parts[i]);
					}

					Namespace namespace = getOrCreateNamespace(plugin.program, namespacePath.toString());

					e.primaryFunctionSymbol.setNameAndNamespace(methodName, namespace, SourceType.IMPORTED);
				} else {
					e.primaryFunctionSymbol.setName(e.secondaryFunctionName, SourceType.IMPORTED);
				}

				e.do_import = false;
			} catch (Exception ex) {
				exp = ex;
			}

			changes.put(transformation, exp);
		}

		plugin.program.endTransaction(trans, true);

		String html = "<html><ul>";

		for (var c : changes.entrySet()) {
			boolean wasSuccess = c.getValue() == null;

			String color = wasSuccess ? "green" : "red";

			html += "<li><font color='" + color + "'>" + c.getKey();

			if (!wasSuccess) {
				html += " unsuccessful (Exception: " + c.getValue().toString() + ")";
			}

			html += "</font></li>";
		}

		html += "</ul></html>";

		plugin.provider.refresh();
		Msg.showInfo(this, plugin.provider.getComponent(), "Renamed functions", html);
	}
}

class ImportCheckedFunctionNamesAction extends ImportFunctionNamesAction {
	public ImportCheckedFunctionNamesAction(BinDiffHelperPlugin plugin) {
		super("Import selected function names", plugin);

		this.setMenuBarData(new MenuData(new String[] { "Import", "Checked functions' names" }, "Import"));

		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/table_go.png"), "Import"));

		setDescription(HTMLUtilities.toHTML("Import checked functions' names"));
	}

	@Override
	protected boolean shouldImportEntry(ComparisonTableModel.Entry e) {
		return e.do_import;
	}
}

class ImportAllFunctionNamesAction extends ImportFunctionNamesAction {
	public ImportAllFunctionNamesAction(BinDiffHelperPlugin plugin) {
		super("Import all function names", plugin);

		this.setMenuBarData(new MenuData(new String[] { "Import", "All functions' names" }, "Import"));

		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/table_lightning.png"), "Import"));

		setDescription(HTMLUtilities.toHTML("Import all function names"));
	}

	@Override
	protected boolean shouldImportEntry(ComparisonTableModel.Entry e) {
		return true;
	}
}

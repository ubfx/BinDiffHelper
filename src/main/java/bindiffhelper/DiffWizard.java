package bindiffhelper;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collections;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import bindiffhelper.BinDiffHelperProvider.DiffState;
import docking.Tool;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionListener;
import docking.wizard.AbstractWizardJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.PanelManager;
import docking.wizard.WizardManager;
import docking.wizard.WizardPanel;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

class DiffKindPanel extends AbstractWizardJPanel {
	private JRadioButton rbFromProject, rbFromExternal;
	private GhidraFileChooserPanel extBDFilePanel;

	private BinDiffHelperPlugin plugin;

	private boolean loadedFromProject = false;

	DiffKindPanel(BinDiffHelperPlugin plugin) {
		super(new GridLayout(2, 1, 10, 10));
		// setBorder(NewProjectPanelManager.EMPTY_BORDER);

		this.plugin = plugin;
		ButtonGroup bg = new ButtonGroup();

		rbFromProject = new JRadioButton("Diff with other file from ghidra project (select in next panel)");
		bg.add(rbFromProject);

		JPanel fromProjectPanel = new JPanel();
		fromProjectPanel.setLayout(new BoxLayout(fromProjectPanel, BoxLayout.Y_AXIS));
		fromProjectPanel.add(rbFromProject);
		fromProjectPanel.setBorder(BorderFactory.createLineBorder(Color.BLACK));

		if (!plugin.provider.hasExporter || plugin.binDiffBinary == null) {
			rbFromProject.setEnabled(false);
			JLabel lab = new JLabel("BinExport2 plugin or BinDiff binary not found - this feature is disabled.");
			fromProjectPanel.add(lab);
		}
		add(fromProjectPanel);

		rbFromExternal = new JRadioButton("Use externally created .BinDiff file");
		bg.add(rbFromExternal);

		JPanel extPanel = new JPanel();
		extPanel.setLayout(new BoxLayout(extPanel, BoxLayout.Y_AXIS));
		extPanel.add(rbFromExternal);
		extPanel.setBorder(BorderFactory.createLineBorder(Color.BLACK));

		extBDFilePanel = new GhidraFileChooserPanel("", "de.ubfx.bindiffhelper.extbdfile", "", true,
				GhidraFileChooserPanel.INPUT_MODE);
		extBDFilePanel.setBorder(BorderFactory.createEmptyBorder());
		extBDFilePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

		extPanel.add(extBDFilePanel);

		JButton extLoadBtn = new JButton("Load");
		extLoadBtn.addActionListener(e -> loadCallback());
		extPanel.add(extLoadBtn);
		add(extPanel);

		if (rbFromProject.isEnabled())
			rbFromProject.setSelected(true);
		else
			rbFromExternal.setSelected(true);

		ActionListener validityListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				notifyListenersOfValidityChanged();
			}
		};

		rbFromProject.addActionListener(validityListener);
		rbFromExternal.addActionListener(validityListener);
	}

	protected void loadCallback() {
		try {
			plugin.provider.openExternalDB(extBDFilePanel.getFileName());
			rbFromExternal.setSelected(true);
			loadedFromProject = true;
		} catch (Exception e) {
			e.printStackTrace();
			loadedFromProject = false;
		}
		notifyListenersOfValidityChanged();
	}

	@Override
	public String getTitle() {
		return "Choose diffing method";
	}

	@Override
	public boolean isValidInformation() {
		if (rbFromProject.isSelected())
			return true;

		return loadedFromProject;
	}

	@Override
	public void initialize() {
	}

	public boolean isFromProject() {
		return rbFromProject.isSelected();
	}
}

class MatchPanel extends AbstractWizardJPanel {
	private JRadioButton rb0;
	private JRadioButton rb1;
	private BinDiffHelperPlugin plugin;

	private String buildTable(String fn, String fnColor, String efn, String efnColor, String hash, String hashColor) {
		return "<html><table>" + "<tr><td>Filename</td><td style='color: " + fnColor + ";'>" + fn + "</td></tr>"
				+ "<tr><td>Binary Filename</td><td style='color: " + efnColor + ";'>" + efn + "</td></tr>"
				+ "<tr><td>SHA256</td><td style='color: " + hashColor + ";'>" + hash + "</td></tr>" + "</table></html>";
	}

	MatchPanel(BinDiffHelperPlugin plugin) {
		super();

		this.plugin = plugin;

		JLabel instructions = new JLabel("<html><p style='width:300px;text-align:center;'>"
				+ "The external BinDiff database has been loaded. "
				+ "Below, you need to select which of the files in the database matches the file loaded in Ghidra.<br/>"
				+ "The <b>other</b> file will be used to import function names from.</p><br/><br/></html>");

		JPanel work = new JPanel(new BorderLayout());
		work.add(instructions, BorderLayout.CENTER);

		JPanel panel = new JPanel(new BorderLayout());

		JPanel ref = new JPanel();
		JPanel bd1 = new JPanel(new BorderLayout());
		JPanel bd2 = new JPanel(new BorderLayout());

		rb0 = new JRadioButton("This file matches the loaded file");
		rb1 = new JRadioButton("This file matches the loaded file");

		ButtonGroup bg = new ButtonGroup();
		bg.add(rb0);
		bg.add(rb1);

		bd1.add(rb0, BorderLayout.PAGE_START);
		bd2.add(rb1, BorderLayout.PAGE_START);

		ref.setBorder(BorderFactory.createTitledBorder("File loaded in Ghidra"));
		bd1.setBorder(BorderFactory.createTitledBorder("First file in BinDiff database"));
		bd2.setBorder(BorderFactory.createTitledBorder("Second file in BinDiff database"));

		panel.add(ref, BorderLayout.PAGE_START);
		panel.add(bd1, BorderLayout.LINE_START);
		panel.add(bd2, BorderLayout.LINE_END);

		Program program = plugin.provider.program;

		String hashRef = program.getExecutableSHA256();
		String fnRef = program.getDomainFile().getName().toString();
		String efnRef = program.getName();

		String fnCol = fnRef.equalsIgnoreCase(plugin.provider.primary.filename) ? "green" : "red";
		String efnCol = efnRef.equalsIgnoreCase(plugin.provider.primary.exefilename) ? "green" : "red";
		String hashCol = hashRef.equalsIgnoreCase(plugin.provider.primary.hash) ? "green" : "red";

		ref.add(new JLabel(buildTable(fnRef, "black", efnRef, "black", hashRef, "black")));
		bd1.add(new JLabel(buildTable(plugin.provider.primary.filename, fnCol, plugin.provider.primary.exefilename,
				efnCol, plugin.provider.primary.hash, hashCol)));

		fnCol = fnRef.equalsIgnoreCase(plugin.provider.secondary.filename) ? "green" : "red";
		efnCol = efnRef.equalsIgnoreCase(plugin.provider.secondary.exefilename) ? "green" : "red";
		hashCol = hashRef.equalsIgnoreCase(plugin.provider.secondary.hash) ? "green" : "red";

		bd2.add(new JLabel(buildTable(plugin.provider.secondary.filename, fnCol, plugin.provider.secondary.exefilename,
				efnCol, plugin.provider.secondary.hash, hashCol)));

		work.add(panel, BorderLayout.PAGE_END);

		add(work);

		ActionListener validityListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				notifyListenersOfValidityChanged();
			}
		};

		rb0.addActionListener(validityListener);
		rb1.addActionListener(validityListener);
	}

	@Override
	public String getTitle() {
		return "Match the loaded file to the correct BinDiff file";
	}

	@Override
	public boolean isValidInformation() {
		return rb0.isSelected() || rb1.isSelected();
	}

	@Override
	public void initialize() {
		// TODO Auto-generated method stub
	}

	public boolean isSwapped() {
		return rb1.isSelected();
	}

}

class FromProjectPanel extends AbstractWizardJPanel {
	private BinDiffHelperPlugin plugin;
	private ProjectDataTreePanel tp;

	FromProjectPanel(BinDiffHelperPlugin plugin) {
		this.plugin = plugin;

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));

		JPanel projectPanel;
		if (plugin.provider.hasExporter && plugin.binDiffBinary != null) {
			tp = new ProjectDataTreePanel(null);
			tp.setProjectData(AppInfo.getActiveProject().getName(), AppInfo.getActiveProject().getProjectData());

			tp.setPreferredSize(new Dimension(400, 300));

			projectPanel = tp;
			tp.addTreeSelectionListener(new GTreeSelectionListener() {
				@Override
				public void valueChanged(GTreeSelectionEvent e) {
					notifyListenersOfValidityChanged();
				}
			});
		} else {
			projectPanel = new JPanel();
			projectPanel.add(new JLabel("<html><p style='width:300px;'>BinDiff binary not selected or BinExport "
					+ "plugin not detected so this feature is not available. Check the settings menu.</p></html>"));
		}

		projectPanel.setBorder(BorderFactory.createTitledBorder("Diff with another file from Ghidra project"));
		projectPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		panel.add(projectPanel);

		panel.add(Box.createRigidArea(new Dimension(0, 20)));
		add(panel);
	}

	@Override
	public String getTitle() {
		return "Select a file that will be diffed to the file which you have currently opened in the Code Explorer";
	}

	@Override
	public boolean isValidInformation() {
		if (tp == null || tp.getSelectedItemCount() != 1)
			return false;

		if (tp.getSelectedDomainFolder() != null)
			return false;

		var df = tp.getSelectedDomainFile();
		return df != null;
	}

	@Override
	public void initialize() {
	}

	public DomainFile getDf() {
		return tp.getSelectedDomainFile();
	}
}

class Program2Panel extends AbstractWizardJPanel {
	private BinDiffHelperPlugin plugin;
	private ProjectDataTreePanel tp;
	private JCheckBox cb;

	private Program program;
	private CodeViewerService cvs;

	Program2Panel(BinDiffHelperPlugin plugin) {
		this.plugin = plugin;
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

		cb = new JCheckBox("Attach another ghidra file to the secondary diff file");

		tp = new ProjectDataTreePanel(null);
		tp.setProjectData(AppInfo.getActiveProject().getName(), AppInfo.getActiveProject().getProjectData());

		tp.setPreferredSize(new Dimension(400, 300));

		tp.addTreeSelectionListener(new GTreeSelectionListener() {
			@Override
			public void valueChanged(GTreeSelectionEvent e) {
				notifyListenersOfValidityChanged();
			}
		});

		add(cb);
		add(tp);
		cb.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				notifyListenersOfValidityChanged();
			}
		});
	}

	@Override
	public String getTitle() {
		return "Optionally attach another ghidra file to the secondary diff file";
	}

	@Override
	public boolean isValidInformation() {
		if (!cb.isSelected())
			return true;

		if (tp == null || tp.getSelectedItemCount() != 1)
			return false;

		if (tp.getSelectedDomainFolder() != null)
			return false;

		var df = tp.getSelectedDomainFile();
		return df != null;
	}

	@Override
	public void initialize() {
	}

	public void open() {
		try {
			DomainFile df = tp.getSelectedDomainFile();
			Tool newTool = plugin.getTool().getToolServices().launchDefaultTool(Collections.singletonList(df));
			DomainObject domainObject = df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
			program = (Program) domainObject;
			cvs = newTool.getService(CodeViewerService.class);
		} catch (Exception e) {
			Msg.showError(this, this, "Error", "Failed to open the program in new window: " + e.getMessage());
		}
	}

	public boolean useProgram2() {
		return cb.isSelected();
	}

	public CodeViewerService getCvs() {
		return cvs;
	}

	public Program getProg() {
		return program;
	}
	
	public DomainFile getDf() {
		return tp.getSelectedDomainFile();
	}
}

class DiffPanelManager implements PanelManager {
	private WizardManager wizardMgr;
	private DiffKindPanel dkPanel;
	private MatchPanel matchPanel;
	private FromProjectPanel fromProjectPanel;
	private Program2Panel program2Panel;

	private BinDiffHelperPlugin plugin;

	DiffPanelManager(BinDiffHelperPlugin plugin) {
		dkPanel = new DiffKindPanel(plugin);
		this.plugin = plugin;
	}

	@Override
	public boolean canFinish() {
		WizardPanel curPanel = wizardMgr.getCurrentWizardPanel();
		if (curPanel == null)
			return false;
		if (curPanel == fromProjectPanel)
			return true;
		if (curPanel == program2Panel)
			return true;
		return false;
	}

	@Override
	public boolean hasNextPanel() {
		WizardPanel curPanel = wizardMgr.getCurrentWizardPanel();
		if (curPanel == null)
			return true;
		if (curPanel == fromProjectPanel)
			return false;
		if (curPanel == matchPanel)
			return true;
		if (curPanel == dkPanel)
			return true;
		if (curPanel == program2Panel)
			return false;
		return false;
	}

	@Override
	public boolean hasPreviousPanel() {
		WizardPanel curPanel = wizardMgr.getCurrentWizardPanel();
		if (curPanel == null)
			return false;
		if (curPanel == fromProjectPanel)
			return true;
		if (curPanel == matchPanel)
			return true;
		if (curPanel == dkPanel)
			return false;
		if (curPanel == program2Panel)
			return true;
		return false;
	}

	@Override
	public WizardPanel getNextPanel() throws IllegalPanelStateException {

		if (wizardMgr.getCurrentWizardPanel() == null)
			return dkPanel;

		if (wizardMgr.getCurrentWizardPanel() == dkPanel) {
			if (dkPanel.isFromProject()) {
				fromProjectPanel = new FromProjectPanel(plugin);
				return fromProjectPanel;
			} else {
				matchPanel = new MatchPanel(plugin);
				return matchPanel;
			}
		}

		if (wizardMgr.getCurrentWizardPanel() == matchPanel) {
			program2Panel = new Program2Panel(plugin);
			return program2Panel;
		}

		return null;
	}

	@Override
	public WizardPanel getInitialPanel() throws IllegalPanelStateException {
		return dkPanel;
	}

	@Override
	public WizardPanel getPreviousPanel() throws IllegalPanelStateException {
		WizardPanel curPanel = wizardMgr.getCurrentWizardPanel();
		if (curPanel == null)
			return null;
		if (curPanel == fromProjectPanel)
			return dkPanel;
		if (curPanel == matchPanel)
			return dkPanel;
		if (curPanel == dkPanel)
			return null;
		if (curPanel == program2Panel)
			return matchPanel;
		return null;
	}

	@Override
	public String getStatusMessage() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void finish() throws IllegalPanelStateException {
		WizardPanel curPanel = wizardMgr.getCurrentWizardPanel();
		if (curPanel == program2Panel) {
			if (matchPanel.isSwapped()) {
				DiffState temp = plugin.provider.secondary;
				plugin.provider.secondary = plugin.provider.primary;
				plugin.provider.primary = temp;
			}

			if (program2Panel.useProgram2())
				program2Panel.open();

			plugin.provider.secondary.cvs = program2Panel.getCvs();
			plugin.provider.secondary.prog = program2Panel.getProg();
			plugin.provider.secondary.df = program2Panel.getDf();
			plugin.provider.doDiffWork();
			wizardMgr.close();
		} else {
			// from project
			DomainFile df = fromProjectPanel.getDf();
			plugin.callBinDiff(df, files -> {
				if (files != null) {
					try {
						plugin.provider.openExternalDBWithBinExports(files[2].getAbsolutePath(), files[0], files[1]);
					} catch (Exception e) {
						e.printStackTrace();
					}
					plugin.provider.secondary.df = df;
					try {
						var dof = df.getReadOnlyDomainObject(plugin, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
						if (dof instanceof Program p)
							plugin.provider.secondary.prog = p;
					} catch (Exception e) {
						
					}
					plugin.provider.doDiffWork();
					wizardMgr.close();
				}
			});
		}
	}

	@Override
	public void cancel() {
		// TODO Auto-generated method stub
	}

	@Override
	public void initialize() {
		// TODO Auto-generated method stub
	}

	@Override
	public Dimension getPanelSize() {
		return new Dimension(1000, 400);
	}

	@Override
	public void setWizardManager(WizardManager wm) {
		wizardMgr = wm;
	}

	@Override
	public WizardManager getWizardManager() {
		return wizardMgr;
	}
}

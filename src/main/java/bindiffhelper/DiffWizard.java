package bindiffhelper;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.Collections;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import bindiffhelper.BinDiffHelperProvider.DiffState;
import docking.Tool;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import docking.widgets.filechooser.GhidraFileChooserPanelListener;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionListener;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

class DiffWizardData {
	public boolean isFromProject;
	public boolean isSwapped;
	
	public boolean useProgram2;
	public DomainFile program2Df;
	public Program program2Program;
	public CodeViewerService program2Cvs;

	public DomainFile fromProjectDf;
}

class DiffKindStep extends WizardStep<DiffWizardData> {
	private JRadioButton rbFromProject, rbFromExternal;
	private GhidraFileChooserPanel extBDFilePanel;

	private BinDiffHelperPlugin plugin;

	private JPanel panel;
	
	public DiffKindStep(WizardModel<DiffWizardData> model, BinDiffHelperPlugin plugin) {
		super(model, "Choose diffing method", null);
		this.plugin = plugin;
	}
	
	
	public void initialize(DiffWizardData data) {
		this.panel = new JPanel(new GridLayout(2, 1, 10, 10));
		
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
		this.panel.add(fromProjectPanel);

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
		this.panel.add(extPanel);

		if (rbFromProject.isEnabled())
			rbFromProject.setSelected(true);
		else
			rbFromExternal.setSelected(true);
		
		ActionListener validityListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				notifyStatusChanged();
			}
		};

		rbFromProject.addActionListener(validityListener);
		rbFromExternal.addActionListener(validityListener);
		extBDFilePanel.setListener(new GhidraFileChooserPanelListener() {
			@Override
			public void fileChanged(File file) {
				notifyStatusChanged();
			}

			@Override
			public void fileDropped(File file) {
				notifyStatusChanged();				
			}
		});
	}

	@Override
	public boolean isValid() {
		if (rbFromProject.isSelected())
			return true;
		else if(!extBDFilePanel.getFileName().isBlank())
			return true;
		return false;
	}


	@Override
	public JComponent getComponent() {
		return this.panel;
	}

	@Override
	public boolean canFinish(DiffWizardData data) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void populateData(DiffWizardData data) {
		data.isFromProject = rbFromProject.isSelected();
	}

	@Override
	public boolean apply(DiffWizardData data) {
		if (rbFromExternal.isSelected()) {
			try {
				plugin.provider.openExternalDB(extBDFilePanel.getFileName());
				//loadedFromProject = true;
			} catch (Exception e) {
				e.printStackTrace();
				
				Msg.showError(this, extBDFilePanel, "Error loading", e);
				//loadedFromProject = false;
				
				return false;
			}
		}
		return true;
	}
}

class MatchStep extends WizardStep<DiffWizardData> {
	private JRadioButton rb0;
	private JRadioButton rb1;
	private BinDiffHelperPlugin plugin;

	private JPanel panel;
	
	private String buildTable(String fn, String fnColor, String efn, String efnColor, String hash, String hashColor) {
		hash = hash.substring(0, 12) + "..";
		return "<html><table>" + "<tr><td>Filename</td><td style='color: " + fnColor + ";'>" + fn + "</td></tr>"
				+ "<tr><td>Binary Filename</td><td style='color: " + efnColor + ";'>" + efn + "</td></tr>"
				+ "<tr><td>SHA256</td><td style='color: " + hashColor + ";'>" + hash + "</td></tr>" + "</table></html>";
	}

	MatchStep(WizardModel<DiffWizardData> model, BinDiffHelperPlugin plugin) {
		super(model, "Match the loaded file to the correct BinDiff file", null);

		this.plugin = plugin;
	}
	
	@Override
	public void initialize(DiffWizardData data) {

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

		this.panel = work;
		
		ActionListener validityListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				notifyStatusChanged();
			}
		};
		rb0.addActionListener(validityListener);
		rb1.addActionListener(validityListener);
	}


	@Override
	public boolean isValid() {
		return rb0.isSelected() || rb1.isSelected();
	}


	@Override
	public JComponent getComponent() {
		return this.panel;
	}

	@Override
	public boolean canFinish(DiffWizardData data) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void populateData(DiffWizardData data) {
		data.isSwapped = rb1.isSelected();
	}

	@Override
	public boolean apply(DiffWizardData data) {
		return true;
	}

	public boolean isApplicable(DiffWizardData data) {
		return !data.isFromProject;
	}
}

class FromProjectStep extends WizardStep<DiffWizardData> {
	private BinDiffHelperPlugin plugin;
	private ProjectDataTreePanel tp;
	private JPanel panel;
	
	public FromProjectStep(WizardModel<DiffWizardData> model, BinDiffHelperPlugin plugin) {
		super(model, "Select a file that will be diffed to the file which you have currently opened in the Code Explorer", null);
		this.plugin = plugin;
	}
	
	@Override
	public void initialize(DiffWizardData data) {
		panel = new JPanel();
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
					notifyStatusChanged();
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
	}

	@Override
	public boolean isValid() {
		if (tp == null || tp.getSelectedItemCount() != 1)
			return false;

		if (tp.getSelectedDomainFolder() != null)
			return false;

		var df = tp.getSelectedDomainFile();
		return df != null;
	}

	@Override
	public boolean canFinish(DiffWizardData data) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void populateData(DiffWizardData data) {
		data.fromProjectDf = tp.getSelectedDomainFile();
	}

	@Override
	public boolean apply(DiffWizardData data) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	@Override
	public boolean isApplicable(DiffWizardData data) {
		return data.isFromProject;
	}
}

class Program2Step extends WizardStep<DiffWizardData> {
	private BinDiffHelperPlugin plugin;
	private ProjectDataTreePanel tp;
	private JCheckBox cb;

	private JPanel panel;
	
	public Program2Step(WizardModel<DiffWizardData> model, BinDiffHelperPlugin plugin) {
		super(model, "Optionally attach another ghidra file to the secondary diff file", null);
		this.plugin = plugin;
	}
	
	@Override
	public void initialize(DiffWizardData data) {
		this.panel = new JPanel();
		this.panel.setLayout(new BoxLayout(this.panel, BoxLayout.Y_AXIS));

		cb = new JCheckBox("Attach another ghidra file to the secondary diff file");

		tp = new ProjectDataTreePanel(null);
		tp.setProjectData(AppInfo.getActiveProject().getName(), AppInfo.getActiveProject().getProjectData());

		tp.setPreferredSize(new Dimension(400, 300));

		this.panel.add(cb);
		this.panel.add(tp);

	}


	@Override
	public boolean isValid() {
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
	public boolean canFinish(DiffWizardData data) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void populateData(DiffWizardData data) {
		data.useProgram2 = cb.isSelected();
	}

	@Override
	public boolean apply(DiffWizardData data) {
		if (cb.isSelected()) {
			try {
				data.program2Df = tp.getSelectedDomainFile();
				Tool newTool = plugin.getTool().getToolServices().launchDefaultTool(Collections.singletonList(data.program2Df));
				DomainObject domainObject = data.program2Df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
				data.program2Program = (Program) domainObject;
				data.program2Cvs = newTool.getService(CodeViewerService.class);
			} catch (Exception e) {
				Msg.showError(this, tp, "Error", "Failed to open the program in new window: " + e.getMessage());
				return false;
			}
		}
		return true;
	}

	@Override
	public JComponent getComponent() {
		return this.panel;
	}
	
	@Override
	public boolean isApplicable(DiffWizardData data) {
		return !data.isFromProject;
	}
}

class DiffWizardModel extends WizardModel<DiffWizardData> {
	private BinDiffHelperPlugin plugin;
	
	protected DiffWizardModel(BinDiffHelperPlugin plugin) {
		super("Open Diff", new DiffWizardData());
		this.plugin = plugin;
	}

	@Override protected Dimension getPreferredSize() {
		return new Dimension(500, 400);
	}
	
	@Override
	protected void addWizardSteps(List<WizardStep<DiffWizardData>> steps) {
		steps.add(new DiffKindStep(this, plugin));
		steps.add(new FromProjectStep(this, plugin));
		steps.add(new MatchStep(this, plugin));
		steps.add(new Program2Step(this, plugin));
	}

	@Override
	protected boolean doFinish() {
		if (!data.isFromProject) {
			if (data.isSwapped) {
				DiffState temp = plugin.provider.secondary;
				plugin.provider.secondary = plugin.provider.primary;
				plugin.provider.primary = temp;
			}

			if (data.useProgram2) {
				plugin.provider.secondary.cvs = data.program2Cvs;
				plugin.provider.secondary.prog = data.program2Program;
				plugin.provider.secondary.df = data.program2Df;
			}
			
			plugin.provider.doDiffWork();
		} else {
			// from project
			DomainFile df = data.fromProjectDf;
			
			plugin.callBinDiff(df, files -> {
				if (files != null) {
					try {
						plugin.provider.openExternalDBWithBinExports(files[2].getAbsolutePath(), files[0], files[1]);
					} catch (Exception e) {
						e.printStackTrace();
						Msg.showError(df, null, "error", "Error in openExternalDBWithBinExports() " + e.getLocalizedMessage());
					}
					plugin.provider.secondary.df = df;
					try {
						var dof = df.getReadOnlyDomainObject(plugin, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
						if (dof instanceof Program p)
							plugin.provider.secondary.prog = p;
					} catch (Exception e) {
						Msg.showError(df, null, "error", "error in getReadOnlyDomainObject() " + e.getLocalizedMessage());
					}
					plugin.provider.doDiffWork();
				}
			});
		}
		
		return true;
	}
	
}

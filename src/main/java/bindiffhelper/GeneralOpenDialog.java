package bindiffhelper;

import java.awt.Component;
import java.awt.Dimension;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.util.Msg;
import ghidra.framework.model.DomainFile;

public class GeneralOpenDialog extends DialogComponentProvider {
	
	private ProjectDataTreePanel tp;
	private GhidraFileChooserPanel extBEFilePanel;
	private GhidraFileChooserPanel extBDFilePanel;
	
	private BinDiffHelperPlugin plugin;
	
	public GeneralOpenDialog(BinDiffHelperPlugin plugin)
	{
		super("Open File");
	
		this.plugin = plugin;
		
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
		
		JLabel l = new JLabel("<html><p style='width:300px;'>In this dialog, you can select a file that will be diffed to "
				+ "the file which you have currently opened in the Code Explorer.</p><br/><br/></html>");
				
		panel.add(l);
		
		tp = new ProjectDataTreePanel(null);
		tp.setProjectData(AppInfo.getActiveProject().getName(), AppInfo.getActiveProject().getProjectData());
		tp.setBorder(BorderFactory.createTitledBorder("Diff with another file from Ghidra project"));
		tp.setAlignmentX(Component.LEFT_ALIGNMENT);
		tp.setPreferredSize(new Dimension(400, 300));
		
		panel.add(tp);
		
		panel.add(Box.createRigidArea(new Dimension(0, 20)));
		
		extBEFilePanel = new GhidraFileChooserPanel("", "de.ubfx.bindiffhelper.extbefile",
				"", true, GhidraFileChooserPanel.INPUT_MODE);
		
		extBEFilePanel.setVisible(true);
		
		extBEFilePanel.setBorder(BorderFactory.createTitledBorder("Diff with external BinExport file"));
		extBEFilePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		
		panel.add(extBEFilePanel);
		panel.add(Box.createRigidArea(new Dimension(0, 20)));
		
		extBDFilePanel = new GhidraFileChooserPanel("", "de.ubfx.bindiffhelper.extbdfile",
				"", true, GhidraFileChooserPanel.INPUT_MODE);
		extBDFilePanel.setVisible(true);
		
		extBDFilePanel.setBorder(BorderFactory.createTitledBorder("Use external BinDiff file"));
		extBDFilePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		
		panel.add(extBDFilePanel);
		
		addWorkPanel(panel);

		okButton = new JButton("OK");
		okButton.addActionListener(e -> okCallback());
		addButton(okButton);

		cancelButton = new JButton("Cancel");
		cancelButton.setName("Cancel");
		cancelButton.addActionListener(e -> cancelCallback());
		addButton(cancelButton);
	}

	
	@Override
	protected void okCallback() {
		if (!extBDFilePanel.getFileName().isEmpty()) {
			plugin.provider.openBinDiffDB(extBDFilePanel.getFileName());
		}
		else if (!extBEFilePanel.getFileName().isEmpty()) {
			//
			
		}
		else if (tp.getSelectedItemCount() == 1) {
			if (tp.getSelectedDomainFolder() != null) {
				Msg.showError(this, getComponent(), "Error", 
						"You seem to have selected a folder. Please select a single file.");
				return;
			}
			
			var df = tp.getSelectedDomainFile();
			if (df == null)	{
				Msg.showError(this, getComponent(), "Error", 
						"No valid selection");
				return;
			}
			
			var files = plugin.callBinDiff(df);
			
			plugin.provider.openBinDiffDB(files[2].getAbsolutePath(), files[0], files[1]);
		}
		else {
			Msg.showError(this, getComponent(), "Error", "No valid selection");
		}
		
		close();
	}
}

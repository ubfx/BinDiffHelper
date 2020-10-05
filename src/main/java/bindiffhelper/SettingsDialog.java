package bindiffhelper;

import java.awt.BorderLayout;
import java.io.IOException;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import ghidra.util.Msg;

public class SettingsDialog extends DialogComponentProvider {

	protected BinDiffHelperPlugin plugin;
	protected GhidraFileChooserPanel fileChooserPanel;
	
	public SettingsDialog(BinDiffHelperPlugin plugin) {
		super("Settings");
		
		this.plugin = plugin;
		
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		
		JLabel label = new JLabel("Select the BinDiff 6 binary");
		panel.add(label, BorderLayout.NORTH);
		
		fileChooserPanel = new GhidraFileChooserPanel("BinDiff 6", BinDiffHelperPlugin.BD6BINPROPERTY,
				plugin.binDiff6Binary, true, GhidraFileChooserPanel.INPUT_MODE);
		fileChooserPanel.setVisible(true);
		
		fileChooserPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(fileChooserPanel, BorderLayout.CENTER);
		
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
		close();
		
		try {
			plugin.updateBinDiff6Binary();
		} catch (IOException e) {
			Msg.showError(this, getComponent(), "Error", e.toString());
		}

		plugin.provider.generateWarnings();
	}
}

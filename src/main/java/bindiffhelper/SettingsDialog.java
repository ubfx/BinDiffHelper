package bindiffhelper;

import java.awt.BorderLayout;
import java.io.IOException;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import ghidra.util.Msg;

public class SettingsDialog extends DialogComponentProvider {

	protected BinDiffHelperPlugin plugin;
	protected GhidraFileChooserPanel fileChooserPanel;
	private JTextField customTextField;

	public SettingsDialog(BinDiffHelperPlugin plugin) {
		super("Settings");

		this.plugin = plugin;

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

		JLabel fileChooserLabel = new JLabel("Select the BinDiff 6/7/8 binary");
		panel.add(fileChooserLabel, BorderLayout.NORTH);

		fileChooserPanel = new GhidraFileChooserPanel("BinDiff", BinDiffHelperPlugin.BDBINPROPERTY,
				plugin.binDiffBinary, true, GhidraFileChooserPanel.INPUT_MODE);
		fileChooserPanel.setVisible(true);

		fileChooserPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(fileChooserPanel, BorderLayout.CENTER);

		JPanel diffCommandPanel = new JPanel(new BorderLayout());
		diffCommandPanel.setBorder(BorderFactory.createEmptyBorder());

		JLabel diffCommandLabel = new JLabel("Custom diff command:");
		diffCommandPanel.add(diffCommandLabel, BorderLayout.NORTH);

		JPanel diffCommandTextField = new JPanel(new BorderLayout());
		diffCommandTextField.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		customTextField = new JTextField();
		customTextField.setText(plugin.diffCommand);
		diffCommandTextField.add(customTextField, BorderLayout.CENTER);

		diffCommandPanel.add(diffCommandTextField, BorderLayout.CENTER);
		panel.add(diffCommandPanel, BorderLayout.SOUTH);

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
			plugin.updateBinDiffBinary();
		} catch (IOException e) {
			Msg.showError(this, getComponent(), "Error", e.toString());
		}

		plugin.updateDiffCommand(customTextField.getText());
		plugin.provider.generateWarnings();
	}
}

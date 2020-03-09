package bindiffhelper;

import java.awt.BorderLayout;
import java.util.function.Function;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooserPanel;

public class ImportDialog extends DialogComponentProvider {

	interface Caller
	{
		void importDialogFileSelected(String filename);
	}
	
	private GhidraFileChooserPanel fileChooserPanel;
	
	Caller caller;
	
	public ImportDialog(Caller caller) {
		super("Import BinDiff");
		this.caller = caller;
		
		addWorkPanel(createMainPanel());

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
		
		caller.importDialogFileSelected(fileChooserPanel.getFileName());
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
	
		
		fileChooserPanel = new GhidraFileChooserPanel("Input File", "de.ubfx.bindiffhelper.inputfile",
				"", true, GhidraFileChooserPanel.INPUT_MODE);
		fileChooserPanel.setVisible(true);
		
		fileChooserPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(fileChooserPanel, BorderLayout.NORTH);	
		
		
		return panel;
	}
}

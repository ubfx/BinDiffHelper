package bindiffhelper;

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooserPanel;

public class OpenDialog extends DialogComponentProvider {

	interface Caller
	{
		void importDialogFileSelected(String filename);
	}
	
	private GhidraFileChooserPanel fileChooserPanel;
	
	Caller caller;
	
	public OpenDialog(Caller caller, String title, String propertyname)
	{
		this(caller, title, propertyname, null);
	}
	
	public OpenDialog(Caller caller, String title, String propertyname, String instructions) {
		super("Open File");
		this.caller = caller;
		
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
	
		
		if (instructions != null)
		{
			JLabel label = new JLabel(instructions);
			panel.add(label, BorderLayout.NORTH);
		}
		
		fileChooserPanel = new GhidraFileChooserPanel(title, propertyname,
				"", true, GhidraFileChooserPanel.INPUT_MODE);
		fileChooserPanel.setVisible(true);
		
		fileChooserPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(fileChooserPanel, BorderLayout.SOUTH);
		
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
		
		caller.importDialogFileSelected(fileChooserPanel.getFileName());
	}
}

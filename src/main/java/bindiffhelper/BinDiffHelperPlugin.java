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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.exporter.Exporter;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "This plugin helps importing function names using BinDiff 6",
	description = "This plugin helps importing function names using BinDiff 6",
	servicesRequired = { CodeViewerService.class }
)
//@formatter:on
public class BinDiffHelperPlugin extends ProgramPlugin {

	BinDiffHelperProvider provider;
	Exporter BinExportExporter;
	String binDiff6Binary;
	
	public final static String BD6BINPROPERTY = "de.ubfx.bindiffhelper.bindiff6binary";
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinDiffHelperPlugin(PluginTool tool) {
		super(tool, true, true);

		Preferences.removeProperty(BD6BINPROPERTY);
		BinExportExporter = null;
		binDiff6Binary = Preferences.getProperty(BD6BINPROPERTY);
		
		try {
			Class<?> binExportExporterClass = Class.forName("com.google.security.binexport.BinExportExporter");
			
			List<Exporter> list = new ArrayList<>(ClassSearcher.getInstances(Exporter.class));
			
			for (Exporter e: list)
			{
				if (e.getClass() == binExportExporterClass)
				{
					BinExportExporter = e;
					break;
				}
			}
			
		} catch (ClassNotFoundException e) {
		}

		provider = new BinDiffHelperProvider(this, this.getCurrentProgram());
		provider.setTitle("BinDiffHelper");
		provider.addToTool();
	}

	public boolean updateBinDiff6Binary()
	{
		String bin = Preferences.getProperty(BD6BINPROPERTY);
		binDiff6Binary = null;
		
		if (bin == null || bin.isEmpty()) {
			return false;
		}
		
		File f = new File(bin);
		if (!f.exists() || !f.canExecute())
		{
			Msg.showError(this, provider.getComponent(), "Error", "File does not exist or is not executable");
			return false;
		}
		
		String[] cmd = {bin, ""};
		try {
			var p = Runtime.getRuntime().exec(cmd);
			String outp = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
			
			p.waitFor();
			
			
			if (!outp.startsWith("BinDiff 6"))
			{
				Msg.showError(this, provider.getComponent(), "Error", "This does not seem to be a BinDiff 6 binary");
			}
			
			
		} catch (Exception e) {
			Msg.showError(this, provider.getComponent(), "Error", "Couldn't run this file. Doesn't seem to be the correct BinDiff 6 binary");
			return false;
			
		}
		
		Msg.showInfo(this, provider.getComponent(), "Success", "Successfully linked BinDiff 6 executable");
		
		binDiff6Binary = bin;
		return true;		
	}
	
	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	@Override
	protected void programActivated(Program p)
	{
		provider.setProgram(p);
	}
	
}

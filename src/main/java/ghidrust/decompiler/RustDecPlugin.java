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

package ghidrust.decompiler;

import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.DeveloperPluginPackage;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.ActionContext;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.PluginEvent;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidrust.analyzer.RustStdAnalyzer;

// @formatter:off
/**
 * Add the PluginInfo annotation for the Rust decompiler plugin.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Rust Decompiler",
    description = "Decompile Rust binaries' assembly to Rust code",
    eventsConsumed = {
        ProgramActivatedPluginEvent.class,
        ProgramLocationPluginEvent.class,
        ProgramClosedPluginEvent.class
    }
)
// @formatter:on

public class RustDecPlugin extends Plugin {
    Program program;
    RustDecProvider provider;

    /**
     * Adds docking actions for opening the decompiler and checking whether the
     * binary is a Rust binary.
     *
     * @param tool PluginTool instance responsible for managing RustDecPlugin.
     */
    public RustDecPlugin(PluginTool tool) {
        super(tool);
        provider = new RustDecProvider(this, getName(), null);

        DockingAction decPlugin = new DockingAction("GhidRust", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                provider.activateProvider();
                ;
            }
        };

        decPlugin.setEnabled(true);
        decPlugin.setMenuBarData(new MenuData(new String[] { "GhidRust", "Open decompiler" }));

        DockingAction checkPlugin = new DockingAction("GhidRust", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (RustStdAnalyzer.isRustBinary(program)) {
                    Msg.showInfo(this, null, "GhidRust", "[+] Yes, this may be a Rust binary!");
                } else {
                    Msg.showInfo(this, null, "GhidRust", "[-] No, this may not be a Rust binary!");
                }
            }
        };

        checkPlugin.setEnabled(true);
        checkPlugin.setMenuBarData(new MenuData(
            new String[] { "GhidRust", "Check if Rust binary" }
        ));

        tool.addAction(decPlugin);
        tool.addAction(checkPlugin);
    }

    @Override
    public void processEvent(PluginEvent event) {
        if (event instanceof ProgramActivatedPluginEvent) {
            program = ((ProgramActivatedPluginEvent) event).getActiveProgram();
            provider.setProgram(program);
            provider.setLocation(null);
        } else if (event instanceof ProgramLocationPluginEvent) {
            ProgramLocation location = ((ProgramLocationPluginEvent) event).getLocation();
            provider.setLocation(location.getAddress());
        } else if (event instanceof ProgramClosedPluginEvent) {
            program = null;
            provider.setProgram(program);
            provider.setLocation(null);
        }

        provider.reload();
    }
}

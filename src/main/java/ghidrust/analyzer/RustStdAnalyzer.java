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

package ghidrust.analyzer;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import ghidra.feature.fid.db.FidFileManager;
import ghidra.framework.Application;

import java.io.IOException;
import generic.jar.ResourceFile;

/**
 * Ghidra analyzer plugin to find whether the program is a Rust binary.
 */
public class RustStdAnalyzer extends AbstractAnalyzer {
    private static final byte[][] rustArtifacts = {
            "run with `RUST_BACKTRACE=1` environment variable".getBytes(),
            "called `Option::unwrap()` on a `None` value".getBytes(),
            "called `Result::unwrap()` on an `Err` value".getBytes()
    };
    private static final String ENABLED_PROPERTY = "DecompilerParameterAnalyzer.enabled";

    /**
     * General plugin initialization.
     */
    public RustStdAnalyzer() {
        super("Detect Rust libstd functions",
                // CHECKSTYLE:OFF
                """
                Detects Rust standard library functions from saved signatures and saves analysis time.

                Provided by GhidRust
                """,
                // CHECKSTYLE:ON
                AnalyzerType.FUNCTION_ANALYZER);

        /*
         * This is just one above the priority at which the Function ID analyzer runs
         * (FUNCTION_ID_ANALYSIS - 1)
         * We need to run before the Function ID analyzer runs because we are populating
         * the Function ID analyzer
         * with our own Function ID databases.
         */
        setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before().before());
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        // Make sure the property has not been disabled
        String defaultEnabled = System.getProperty(ENABLED_PROPERTY);
        if (defaultEnabled != null && !Boolean.parseBoolean(defaultEnabled)) {
            return false;
        }

        /*
         * Be enabled by default so that we can make sure the analysis of Rust functions
         * takes place
         */
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        return isRustBinary(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        FidFileManager ffm = FidFileManager.getInstance();
        if (ffm == null) {
            return false;
        }

        ResourceFile dataDir;
        try {
            dataDir = Application.getModuleDataSubDirectory("");
        } catch (IOException exc) {
            log.appendException(exc);
            return false;
        }

        ResourceFile[] libs = dataDir.listFiles();
        for (ResourceFile lib : libs) {
            monitor.checkCanceled();
            ffm.addUserFidFile(lib.getFile(true));
        }

        return true;
    }

    @Override
    public void analysisEnded(Program program) {
        super.analysisEnded(program);
    }

    /**
     * For exposing the Rust checking code. This can be used as an library call
     * by any other plugin relying on this plugin.
     *
     * @param program The program being analyzed.
     * @return True if it is a Rust binaru, false otherwise.
     */
    public static boolean isRustBinary(Program program) {
        /*
         * Taken from
         * https://github.com/mandiant/capa-rules/blob/master/compiler/rust/compiled-
         * with-rust.yml
         */

        Address startSearch = program.getMinAddress();
        for (byte[] searchString : rustArtifacts) {
            Address foundAddr = program.getMemory().findBytes(
                startSearch, searchString, null, true, null
            );
            if (foundAddr != null) {
                return true;
            }
        }

        return false;
    }
}

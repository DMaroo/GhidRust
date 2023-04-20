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

import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.framework.Application;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

public class RustStdAnalyzer extends AbstractAnalyzer {
    private static final String filePath = "/home/dhruv/Education/CS4900/Work/GhidRust/tmp/logs";
    private static BufferedWriter writer;
    private static final byte[][] rust_artifacts = {
            "run with `RUST_BACKTRACE=1` environment variable".getBytes(),
            "called `Option::unwrap()` on a `None` value".getBytes(),
            "called `Result::unwrap()` on an `Err` value".getBytes()
    };
    private static final String ENABLED_PROPERTY = "DecompilerParameterAnalyzer.enabled";

    public RustStdAnalyzer() {
        super("Detect Rust libstd functions",
                "Detects Rust standard library functions from saved signatures and saves analysis time.\n\nProvided by GhidRust",
                AnalyzerType.FUNCTION_ANALYZER);

        /*
         * This is just one above the priority at which the Function ID analyzer runs
         * (FUNCTION_ID_ANALYSIS - 1)
         * We need to run before the Function ID analyzer runs because we are populating
         * the Function ID analyzer
         * with our own Function ID databases.
         */
        setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before().before());

        try {
            writer = new BufferedWriter(new FileWriter(filePath, true));
        } catch (IOException exc) {
            // pass
        }
    }

    private static boolean contains(byte[] hay, byte[] needle) {
        if (hay.length < needle.length) {
            return false;
        }

        for (int i = 0; i <= hay.length - needle.length; i++) {
            int match_len = 0;
            for (int j = 0; j < needle.length; j++) {
                if (needle[j] == hay[i + j]) {
                    match_len++;
                } else {
                    break;
                }
            }
            if (match_len == needle.length) {
                return true;
            }
        }

        return false;
    }

    private static void logToFile(String s) {
        try {
            writer.append(s);
            writer.append("\n");
            writer.flush();
        } catch (IOException exc) {
            // pass
        }
    }

    static private boolean getNextChunk(InputStream stream, byte[] dest, int size) {
        byte end;

        try {
            if (stream.available() <= 0) {
                return false;
            }

            end = (byte) stream.read();
        } catch (IOException exc) {
            return false;
        }

        for (int i = 0; i < size - 1; i++) {
            dest[i] = dest[i + 1];
        }

        dest[size - 1] = end;
        return true;
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        // Make sure the property has not been disabled
        String default_enabled = System.getProperty(ENABLED_PROPERTY);
        if (default_enabled != null && !Boolean.parseBoolean(default_enabled)) {
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

        ResourceFile data_dir;
        try {
            data_dir = Application.getModuleDataSubDirectory("");
        } catch (IOException exc) {
            log.appendException(exc);
            return false;
        }

        ResourceFile[] libs = data_dir.listFiles();
        for (ResourceFile lib : libs) {
            monitor.checkCanceled();
            ffm.addUserFidFile(lib.getFile(true));
        }

        return true;
    }

    @Override
    public void analysisEnded(Program program) {
        super.analysisEnded(program);

        try {
            writer.close();
        } catch (IOException exc) {
            // pass
        }
    }

    /* For exposing the Rust checking code */
    public static boolean isRustBinary(Program program) {
        /*
         * Taken from
         * https://github.com/mandiant/capa-rules/blob/master/compiler/rust/compiled-
         * with-rust.yml
         */

        /* We know that the strings would be found in the .rodata section */
        MemoryBlock rodata = program.getMemory().getBlock(".rodata");

        InputStream stream = rodata.getData();

        int search_len = 0;
        for (byte[] artifact : rust_artifacts) {
            int artifact_len = artifact.length;

            if (artifact_len > search_len) {
                search_len = artifact_len;
            }
        }

        int i = 0;
        byte[] chunk = new byte[search_len];

        try {
            while (stream.available() > 0 && i < chunk.length) {
                chunk[i] = (byte) stream.read();
                i++;
            }
        } catch (IOException exc) {
            return false;
        }

        try {
            while (stream.available() > 0) {
                if (!getNextChunk(stream, chunk, search_len)) {
                    break;
                }

                for (byte[] artifact : rust_artifacts) {
                    if (contains(chunk, artifact)) {
                        /* This is a Rust binary */
                        return true;
                    }
                }

            }
        } catch (IOException exc) {
            return false;
        }

        return false;
    }
}

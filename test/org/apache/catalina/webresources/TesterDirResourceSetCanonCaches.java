/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.webresources;

import java.io.File;
import java.nio.file.Files;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.apache.tomcat.util.compat.JreCompat;

/**
 * Starts a single {@link DirResourceSet} and reports what the CVE-2024-56337 exposure check in
 * {@code DirResourceSet.initInternal()} did. Driven by {@code TestDirResourceSetCanonCaches} which
 * starts this class in a forked JVM with a command line - and, where required, a stubbed
 * {@code Jre21Compat} - that makes the check reachable.
 * <p>
 * Named {@code Tester*} so that the Ant build does not collect it as a test case.
 */
public class TesterDirResourceSetCanonCaches {

    public static void main(String[] args) throws Exception {
        boolean readOnly = args.length > 0 && Boolean.parseBoolean(args[0]);

        final StringBuilder warnings = new StringBuilder();
        Logger root = Logger.getLogger("");
        root.setLevel(Level.ALL);
        root.addHandler(new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    warnings.append("WARN|").append(record.getLoggerName()).append('|')
                            .append(record.getMessage()).append('\n');
                }
            }

            @Override
            public void flush() {
                // NO-OP
            }

            @Override
            public void close() {
                // NO-OP
            }
        });

        System.out.println("INSTANCE=" + JreCompat.getInstance().getClass().getName());
        System.out.println("CANON_CACHES_DISABLED=" + JreCompat.getInstance().isCanonCachesDisabled());

        File base = Files.createTempDirectory("canon-caches").toFile();
        base.deleteOnExit();

        TesterWebResourceRoot webResourceRoot = new TesterWebResourceRoot();
        DirResourceSet dirResourceSet = new DirResourceSet();
        dirResourceSet.setRoot(webResourceRoot);
        dirResourceSet.setWebAppMount("/");
        dirResourceSet.setBase(base.getAbsolutePath());
        dirResourceSet.setInternalPath("/");
        dirResourceSet.setReadOnly(readOnly);

        try {
            dirResourceSet.start();
            System.out.println("START=OK");
        } catch (Throwable t) {
            Throwable cause = t;
            while (cause.getCause() != null) {
                cause = cause.getCause();
            }
            System.out.println("START=FAILED:" + cause.getClass().getName());
        }

        System.out.print(warnings);
        System.out.println("DONE");
    }
}

/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.compat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/**
 * Helpers for testing the canonical file name cache handling added for CVE-2024-56337.
 * <p>
 * The behaviour under test depends on the Java version the JVM is running on and on the command
 * line the JVM was started with. Neither can be changed from within a running test JVM so the
 * tests have to drive a forked JVM and assert on the markers it writes to standard out.
 */
public class TesterCanonCaches {

    private static final String COMPAT_SOURCE_DIR = "java/org/apache/tomcat/util/compat/";

    /*
     * The JreCompat implementations for Java 21 onwards and the text that has to be replaced in each of their
     * isSupported() methods to make them report that they are not supported. Every implementation from Java 21 onwards
     * has to be stubbed as the test JVM may be running on any of those versions.
     */
    private static final String[][] STUBS = {
            { "Jre21Compat", "return ofVirtualMethod != null;" },
            { "Jre22Compat", "return supported;" } };

    private TesterCanonCaches() {
        // Utility class. Hide default constructor.
    }


    /**
     * Compiles copies of {@code Jre21Compat} and {@code Jre22Compat} whose {@code isSupported()}
     * methods return {@code false}. Placing the resulting directory at the head of a JVM's class
     * path makes {@link JreCompat#getInstance()} select the {@code Jre19Compat} branch - and hence
     * the {@code Jre12Compat} canonical file name cache logic - even when running on Java 21 or
     * later. That is the only way to reach the "Java 12 to 20" code path (and the code in
     * {@code DirResourceSet.initInternal()} that depends on it) on a Java 21+ test JVM.
     *
     * @param workDir The directory in which the stub is generated
     *
     * @return The directory containing the compiled stub or {@code null} if no Java compiler is
     *             available in this JVM
     *
     * @throws IOException If the stub could not be generated
     */
    public static File buildJre21CompatStub(File workDir) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            return null;
        }

        File stubSrcDir = new File(workDir, "stub-src/org/apache/tomcat/util/compat");
        if (!stubSrcDir.mkdirs() && !stubSrcDir.isDirectory()) {
            throw new IOException("Unable to create [" + stubSrcDir + "]");
        }

        List<String> compilerArgs = new ArrayList<>();
        compilerArgs.add("-nowarn");
        compilerArgs.add("-cp");
        compilerArgs.add(System.getProperty("java.class.path"));
        compilerArgs.add("-d");

        File stubClasses = new File(workDir, "stub-classes");
        if (!stubClasses.mkdirs() && !stubClasses.isDirectory()) {
            throw new IOException("Unable to create [" + stubClasses + "]");
        }
        compilerArgs.add(stubClasses.getAbsolutePath());

        for (String[] stubDef : STUBS) {
            String sourcePath = COMPAT_SOURCE_DIR + stubDef[0] + ".java";
            String source = new String(Files.readAllBytes(Paths.get(sourcePath)), StandardCharsets.ISO_8859_1);
            String stub = source.replace(stubDef[1], "return false;");
            if (stub.equals(source)) {
                throw new IOException("Unable to generate a stub from [" + sourcePath + "]");
            }
            File stubSrc = new File(stubSrcDir, stubDef[0] + ".java");
            Files.write(stubSrc.toPath(), stub.getBytes(StandardCharsets.ISO_8859_1));
            compilerArgs.add(stubSrc.getAbsolutePath());
        }

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int result = compiler.run(null, null, err, compilerArgs.toArray(new String[0]));
        if (result != 0) {
            throw new IOException("Failed to compile the JreCompat stubs: " + err.toString("UTF-8"));
        }

        return stubClasses;
    }


    /**
     * Runs the given class in a forked JVM and returns everything it wrote to standard out and
     * standard error.
     *
     * @param prependToClassPath Optional directory to place at the head of the class path
     * @param jvmArgs            Additional JVM arguments
     * @param main               The class to run
     * @param args               The arguments for the class to run
     *
     * @return The output of the forked JVM
     *
     * @throws IOException          If the JVM could not be started or its output could not be read
     * @throws InterruptedException If the current thread is interrupted while waiting for the JVM
     */
    public static String fork(File prependToClassPath, List<String> jvmArgs, Class<?> main, String... args)
            throws IOException, InterruptedException {

        String classPath = System.getProperty("java.class.path");
        if (prependToClassPath != null) {
            classPath = prependToClassPath.getAbsolutePath() + File.pathSeparator + classPath;
        }

        List<String> command = new ArrayList<>();
        command.add(new File(new File(System.getProperty("java.home"), "bin"), "java").getAbsolutePath());
        command.add("-cp");
        command.add(classPath);
        command.addAll(jvmArgs);
        command.add(main.getName());
        for (String arg : args) {
            command.add(arg);
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = p.getInputStream()) {
            byte[] buf = new byte[4096];
            int read = is.read(buf);
            while (read > 0) {
                baos.write(buf, 0, read);
                read = is.read(buf);
            }
        }
        if (!p.waitFor(120, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("Forked JVM did not complete within 120s. Output:\n" + baos.toString("UTF-8"));
        }

        return baos.toString("UTF-8");
    }
}

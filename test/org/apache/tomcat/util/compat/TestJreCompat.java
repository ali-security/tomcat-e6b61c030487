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

import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.tomcat.util.res.StringManager;

/**
 * Tests the canonical file name cache support added to fix CVE-2024-56337.
 */
public class TestJreCompat {

    private static final StringManager sm = StringManager.getManager(JreCompat.class);

    private static final String USE_CANON_CACHES_TRUE = "-Dsun.io.useCanonCaches=true";
    private static final String USE_CANON_CACHES_FALSE = "-Dsun.io.useCanonCaches=false";


    /**
     * The Java 12 to 20 canonical file name cache logic only takes effect if {@code Jre12Compat}
     * is part of the inheritance chain used for every Java version from 12 onwards. If
     * {@code Jre16Compat} is not re-parented onto {@code Jre12Compat} the Java 11 logic - which
     * assumes the cache is enabled - is silently used instead.
     */
    @Test
    public void testJre12CompatIsInTheChain() {
        Assert.assertTrue(JreCompat.isJre12Available());
        Assert.assertTrue("JreCompat.getInstance() returned [" + JreCompat.getInstance().getClass().getName() +
                "] which does not extend Jre12Compat", JreCompat.getInstance() instanceof Jre12Compat);
    }


    /**
     * The canonical file name cache was removed in Java 21 so nothing needs to be (or can be)
     * disabled. Without the Jre21Compat override the base implementation would try - and fail - to
     * find the java.io.FileSystem.useCanonCaches field.
     */
    @Test
    public void testCanonCachesAlwaysDisabledOnJava21() {
        Assume.assumeTrue(JreCompat.isJre21Available());
        Assert.assertTrue(JreCompat.getInstance().isCanonCachesDisabled());
        Assert.assertTrue(JreCompat.getInstance().disableCanonCaches());
    }


    @Test
    public void testMessagesAreDefined() {
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.failed"));
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.init"));
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.java18"));
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.none"));
        Assert.assertNotNull(StringManager.getManager(Jre12Compat.class).getString("jre12Compat.javaPre12"));
    }


    /**
     * Java 11 enables the cache by default. Unless the command line explicitly disables it, Tomcat
     * has to assume it is enabled - this is the case that makes a web application vulnerable to
     * CVE-2024-56337.
     */
    @Test
    public void testJava11DefaultIsCacheEnabled() throws Exception {
        doTestCommandLine(Collections.<String> emptyList(), false, true);
    }


    /**
     * The mitigation the start-up scripts apply. Both implementations have to recognise it.
     */
    @Test
    public void testCommandLineDisablesCache() throws Exception {
        doTestCommandLine(Collections.singletonList(USE_CANON_CACHES_FALSE), true, true);
    }


    /**
     * A user explicitly re-enabling the cache re-introduces the exposure on every Java version
     * that still has the cache. Neither implementation may report the cache as disabled.
     */
    @Test
    public void testCommandLineEnablesCache() throws Exception {
        doTestCommandLine(Collections.singletonList(USE_CANON_CACHES_TRUE), false, false);
    }


    private void doTestCommandLine(List<String> jvmArgs, boolean expectedBase, boolean expectedJre12)
            throws Exception {
        String output = TesterCanonCaches.fork(null, jvmArgs, TesterJreCompatCanonCaches.class);

        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        assertMarker(output, "BASE_DISABLED=" + expectedBase);
        assertMarker(output, "JRE12_DISABLED=" + expectedJre12);
    }


    private void assertMarker(String output, String marker) {
        Assert.assertTrue("Expected [" + marker + "] in the output of the forked JVM:\n" + output,
                output.contains(marker + System.lineSeparator()) || output.contains(marker + "\n"));
    }
}

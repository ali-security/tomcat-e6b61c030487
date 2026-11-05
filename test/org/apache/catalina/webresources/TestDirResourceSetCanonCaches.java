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
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.WebResourceLockSet.ResourceLock;
import org.apache.catalina.startup.ExpandWar;
import org.apache.tomcat.util.compat.TesterCanonCaches;
import org.apache.tomcat.util.res.StringManager;

/**
 * Tests the CVE-2024-56337 exposure check added to {@link DirResourceSet} plus the associated
 * change that makes the CVE-2024-50379 resource locks case insensitive.
 * <p>
 * The exposure check can only run on a JVM where the canonical file name cache still exists (Java
 * 20 and earlier) so the tests that need it fork a JVM with a stubbed {@code Jre21Compat} that
 * forces the "Java 12 to 20" code path.
 */
public class TestDirResourceSetCanonCaches {

    private static final StringManager sm = StringManager.getManager(DirResourceSet.class);

    private static final String USE_CANON_CACHES_TRUE = "-Dsun.io.useCanonCaches=true";
    private static final String USE_CANON_CACHES_FALSE = "-Dsun.io.useCanonCaches=false";

    /**
     * Fragment of {@code dirResourceSet.canonCaches.enabled}. Logged when Tomcat cannot confirm
     * that the canonical file name cache has been disabled.
     */
    private static final String EXPOSED_WARNING = "may be exposed to CVE-2024-56337";

    /**
     * {@code jreCompat.useCanonCaches.none}. Only logged if the exposure check actually attempted
     * to disable the cache.
     */
    private static final String DISABLE_ATTEMPTED_WARNING =
            "No reference to the java.io.FileSystem.useCanonCaches static field available";

    private static File workDir;
    private static File stubDir;


    @BeforeClass
    public static void setup() throws Exception {
        workDir = Files.createTempDirectory("canon-caches-stub").toFile();
        stubDir = TesterCanonCaches.buildJre21CompatStub(workDir);
    }


    @AfterClass
    public static void cleanup() {
        if (workDir != null) {
            ExpandWar.delete(workDir);
        }
    }


    @Test
    public void testMessagesAreDefined() {
        Assert.assertNotNull(sm.getString("dirResourceSet.canonCaches.disabled"));
        String exposed = sm.getString("dirResourceSet.canonCaches.enabled");
        Assert.assertNotNull(exposed);
        Assert.assertTrue(exposed.contains(EXPOSED_WARNING));
    }


    /**
     * The vulnerable scenario: a writable resource set is started on a JVM where Tomcat cannot
     * confirm the canonical file name cache is disabled. Tomcat must notice, must try to disable
     * the cache and must warn that the resource set may be exposed.
     * <p>
     * Seal: upstream throws an IllegalStateException here, preventing the web application from
     * starting. This build warns instead so that the sealed library remains a drop-in
     * replacement, hence the assertion that start-up still succeeds.
     */
    @Test
    public void testCanonCachesEnabledIsDetected() throws Exception {
        String output = forkWithStub(Collections.singletonList(USE_CANON_CACHES_TRUE), false);

        Assert.assertTrue("The Jre21Compat stub did not take effect. Output:\n" + output,
                output.contains("INSTANCE=org.apache.tomcat.util.compat.Jre19Compat"));
        Assert.assertTrue("The canonical file name cache should have been reported as enabled:\n" + output,
                output.contains("CANON_CACHES_DISABLED=false"));
        Assert.assertTrue("Tomcat did not try to disable the canonical file name cache:\n" + output,
                output.contains(DISABLE_ATTEMPTED_WARNING));
        Assert.assertTrue("No CVE-2024-56337 exposure warning was logged:\n" + output,
                output.contains("WARN|org.apache.catalina.webresources.DirResourceSet|") &&
                        output.contains(EXPOSED_WARNING));
        Assert.assertTrue("The WebResourceSet failed to start:\n" + output, output.contains("START=OK"));
    }


    /**
     * The mitigation the start-up scripts apply. No warning, and the cache is never touched.
     */
    @Test
    public void testCanonCachesDisabledOnTheCommandLine() throws Exception {
        String output = forkWithStub(Collections.singletonList(USE_CANON_CACHES_FALSE), false);

        Assert.assertTrue("The Jre21Compat stub did not take effect. Output:\n" + output,
                output.contains("INSTANCE=org.apache.tomcat.util.compat.Jre19Compat"));
        Assert.assertTrue(output.contains("CANON_CACHES_DISABLED=true"));
        Assert.assertFalse("An exposure warning was logged for a protected JVM:\n" + output,
                output.contains(EXPOSED_WARNING));
        Assert.assertTrue(output.contains("START=OK"));
    }


    /**
     * Neither CVE-2024-56337 nor CVE-2024-50379 is exploitable against a read only resource set so
     * the check must not fire - and must not disable the cache - for one.
     */
    @Test
    public void testReadOnlyResourceSetIsNotChecked() throws Exception {
        String output = forkWithStub(Collections.singletonList(USE_CANON_CACHES_TRUE), true);

        Assert.assertTrue("The Jre21Compat stub did not take effect. Output:\n" + output,
                output.contains("INSTANCE=org.apache.tomcat.util.compat.Jre19Compat"));
        Assert.assertTrue(output.contains("CANON_CACHES_DISABLED=false"));
        Assert.assertFalse("An exposure warning was logged for a read only WebResourceSet:\n" + output,
                output.contains(EXPOSED_WARNING));
        Assert.assertFalse("The cache was touched for a read only WebResourceSet:\n" + output,
                output.contains(DISABLE_ATTEMPTED_WARNING));
        Assert.assertTrue(output.contains("START=OK"));
    }


    /**
     * The lock introduced for CVE-2024-50379 only protects against the race if the same lock is
     * used for every spelling of a file name that the file system - or the canonical file name
     * cache - considers equal. If a read of {@code /FOO.JSP} can proceed while {@code /foo.jsp} is
     * locked for writing then the two operations are not mutually exclusive and the resource can
     * still be observed in an inconsistent state.
     */
    @Test
    public void testLockKeysAreCaseInsensitive() throws Exception {
        File base = Files.createTempDirectory("lock-key").toFile();
        try {
            TesterWebResourceRoot root = new TesterWebResourceRoot();
            final DirResourceSet dirResourceSet = new DirResourceSet(root, "/", base.getAbsolutePath(), "/");

            ResourceLock writeLock = dirResourceSet.lockForWrite("/foo.jsp");

            final CountDownLatch readLockAcquired = new CountDownLatch(1);
            final AtomicReference<ResourceLock> readLock = new AtomicReference<>();
            Thread reader = new Thread(() -> {
                // A read lock is owned by the thread that acquired it so it must release it too.
                ResourceLock lock = dirResourceSet.lockForRead("/FOO.JSP");
                readLock.set(lock);
                readLockAcquired.countDown();
                dirResourceSet.unlockForRead(lock);
            });
            reader.setDaemon(true);
            reader.start();

            Assert.assertFalse("A read lock for [/FOO.JSP] was granted while [/foo.jsp] was locked for writing",
                    readLockAcquired.await(2, TimeUnit.SECONDS));

            dirResourceSet.unlockForWrite(writeLock);

            Assert.assertTrue("The read lock for [/FOO.JSP] was never granted",
                    readLockAcquired.await(10, TimeUnit.SECONDS));
            reader.join(10000);

            Assert.assertSame(writeLock, readLock.get());
            Assert.assertEquals("/foo.jsp", writeLock.key);
        } finally {
            ExpandWar.delete(base);
        }
    }


    private String forkWithStub(List<String> jvmArgs, boolean readOnly) throws Exception {
        Assume.assumeTrue("No Java compiler available to build the Jre21Compat stub", stubDir != null);
        return TesterCanonCaches.fork(stubDir, jvmArgs, TesterDirResourceSetCanonCaches.class,
                Boolean.toString(readOnly));
    }
}

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
package org.apache.catalina.core;

import java.lang.reflect.Field;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.tomcat.util.compat.JreCompat;

/**
 * Tests that {@link OpenSSLLifecycleListener} fails securely (prevents the server from initialising) when FIPS mode
 * is requested but cannot be activated.
 */
public class TestOpenSSLLifecycleListener {

    private Boolean originalJre22Available;


    @Before
    public void forceJre22() {
        // The FIPS handling of the listener is only reachable when the FFM API (Java 22+) is available. On older JREs
        // force JreCompat to report Java 22 so the listener logic is exercised. Test classes run in their own JVM.
        if (!JreCompat.isJre22Available()) {
            originalJre22Available = setJre22Available(true);
            Assume.assumeTrue("Unable to force Java 22 code path", JreCompat.isJre22Available());
        }
    }


    @After
    public void restoreJre22() {
        if (originalJre22Available != null) {
            setJre22Available(originalJre22Available.booleanValue());
            originalJre22Available = null;
        }
    }


    @Test
    public void testFIPSRequestedButNotActiveThrowsError() {
        TesterOpenSSLLifecycleListener listener = new TesterOpenSSLLifecycleListener("on", false);
        StandardServer server = new StandardServer();
        try {
            listener.lifecycleEvent(new LifecycleEvent(server, Lifecycle.BEFORE_INIT_EVENT, null));
            Assert.fail("Init must fail when FIPS mode is requested but not active");
        } catch (Error e) {
            Assert.assertEquals(
                    OpenSSLLifecycleListener.sm.getString("openssllistener.initializeFIPSFailed"), e.getMessage());
        }
    }


    @Test
    public void testFIPSRequestedButNotActiveFailsServerInit() throws Exception {
        StandardServer server = new StandardServer();
        server.addLifecycleListener(new TesterOpenSSLLifecycleListener("on", false));
        try {
            server.init();
            Assert.fail("Server must not initialise when FIPS mode is requested but not active");
        } catch (LifecycleException e) {
            Assert.assertTrue(e.getCause() instanceof Error);
            Assert.assertEquals(
                    OpenSSLLifecycleListener.sm.getString("openssllistener.initializeFIPSFailed"),
                    e.getCause().getMessage());
        }
        Assert.assertEquals(LifecycleState.FAILED, server.getState());
    }


    @Test
    public void testFIPSRequiredButNotActiveFailsServerInit() throws Exception {
        StandardServer server = new StandardServer();
        server.addLifecycleListener(new TesterOpenSSLLifecycleListener("require", false));
        try {
            server.init();
            Assert.fail("Server must not initialise when FIPS mode is required but not active");
        } catch (LifecycleException e) {
            Assert.assertTrue(e.getCause() instanceof Error);
        }
        Assert.assertEquals(LifecycleState.FAILED, server.getState());
    }


    @Test
    public void testFIPSRequestedAndActive() throws Exception {
        doTestServerInitSucceeds(new TesterOpenSSLLifecycleListener("on", true));
    }


    @Test
    public void testFIPSOff() throws Exception {
        doTestServerInitSucceeds(new TesterOpenSSLLifecycleListener("off", false));
    }


    @Test
    public void testFIPSNotSet() throws Exception {
        doTestServerInitSucceeds(new TesterOpenSSLLifecycleListener(null, false));
    }


    private void doTestServerInitSucceeds(OpenSSLLifecycleListener listener) throws Exception {
        StandardServer server = new StandardServer();
        server.addLifecycleListener(listener);
        server.init();
        Assert.assertEquals(LifecycleState.INITIALIZED, server.getState());
        server.destroy();
        Assert.assertEquals(LifecycleState.DESTROYED, server.getState());
    }


    /*
     * Changes the value reported by JreCompat.isJre22Available() and returns the previous value or null if the value
     * could not be changed.
     */
    private static Boolean setJre22Available(boolean value) {
        try {
            // Ensure JreCompat is initialised so the static initialiser does not overwrite the new value
            boolean original = JreCompat.isJre22Available();
            Field field = JreCompat.class.getDeclaredField("jre22Available");
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Object unsafe = theUnsafe.get(null);
            Object base = unsafeClass.getMethod("staticFieldBase", Field.class).invoke(unsafe, field);
            Object offset = unsafeClass.getMethod("staticFieldOffset", Field.class).invoke(unsafe, field);
            unsafeClass.getMethod("putBooleanVolatile", Object.class, long.class, boolean.class).invoke(unsafe, base,
                    offset, Boolean.valueOf(value));
            return Boolean.valueOf(original);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }


    private static class TesterOpenSSLLifecycleListener extends OpenSSLLifecycleListener {

        private final String fipsMode;
        private final boolean fipsModeActive;

        TesterOpenSSLLifecycleListener(String fipsMode, boolean fipsModeActive) {
            this.fipsMode = fipsMode;
            this.fipsModeActive = fipsModeActive;
        }

        @Override
        public String getFIPSMode() {
            return fipsMode;
        }

        @Override
        public boolean isFIPSModeActive() {
            return fipsModeActive;
        }
    }
}

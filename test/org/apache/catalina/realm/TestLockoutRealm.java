/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Locale;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.tomcat.unittest.TesterContext;

public class TestLockoutRealm {

    private static final String USER_NAME = "user";
    private static final String PASSWORD = "password";

    private LockOutRealm realm;


    @Before
    public void init() throws Exception {
        Context context = new TesterContext();
        TesterMapRealm tmr = new TesterMapRealm();
        tmr.setContainer(context);
        MessageDigestCredentialHandler ch = new MessageDigestCredentialHandler();
        tmr.setCredentialHandler(ch);
        tmr.addUser(USER_NAME, PASSWORD);
        tmr.start();

        realm = new LockOutRealm();
        realm.setContainer(context);
        realm.addRealm(tmr);
        realm.setFailureCount(2);
        realm.start();
    }


    @Test
    public void testLockoutAfterFailure() {
        Principal p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNotNull(p);

        p = realm.authenticate(USER_NAME, "wrong");
        p = realm.authenticate(USER_NAME, "wrong");
        // Should be locked now
        p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNull(p);
    }


    @Test
    public void testLockoutAfterFailureCaseSensitiveDefault() {
        Principal p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNotNull(p);

        p = realm.authenticate(USER_NAME, "wrong");
        p = realm.authenticate(USER_NAME.toUpperCase(Locale.ENGLISH), "wrong");
        // Should be locked now
        p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNull(p);
    }


    @Test
    public void testLockoutAfterFailureCaseSensitiveFalse() {
        realm.setCaseSensitive(false);

        Principal p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNotNull(p);

        p = realm.authenticate(USER_NAME, "wrong");
        p = realm.authenticate(USER_NAME.toUpperCase(Locale.ENGLISH), "wrong");
        // Should be locked now
        p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNull(p);
    }


    @Test
    public void testLockoutAfterFailureCaseSensitiveTrue() {
        realm.setCaseSensitive(true);

        Principal p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNotNull(p);

        p = realm.authenticate(USER_NAME, "wrong");
        p = realm.authenticate(USER_NAME.toUpperCase(Locale.ENGLISH), "wrong");
        // Should not be locked yet
        p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNotNull(p);

        p = realm.authenticate(USER_NAME, "wrong");
        p = realm.authenticate(USER_NAME, "wrong");

        // Both should be locked now
        p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNull(p);
    }


    @Test
    public void testLockedUserCaseVariant() {
        realm.authenticate(USER_NAME, "wrong");
        realm.authenticate(USER_NAME, "wrong");

        // A case variant of a locked user name must not evade the lock
        Assert.assertTrue(realm.isLocked(USER_NAME));
        Assert.assertTrue(realm.isLocked(USER_NAME.toUpperCase(Locale.ENGLISH)));
        Assert.assertTrue(realm.isLocked("UsEr"));
    }


    @Test
    public void testUnlockCaseInsensitive() {
        realm.authenticate(USER_NAME, "wrong");
        realm.authenticate(USER_NAME, "wrong");
        Assert.assertTrue(realm.isLocked(USER_NAME));

        realm.unlock(USER_NAME.toUpperCase(Locale.ENGLISH));

        Assert.assertFalse(realm.isLocked(USER_NAME));
        Principal p = realm.authenticate(USER_NAME, PASSWORD);
        Assert.assertNotNull(p);
    }


    @Test
    public void testIsLockedNullUser() {
        Assert.assertFalse(realm.isLocked(null));
        // Client certificate authentication with no certificates passes a null user name through the lock checks
        Principal p = realm.authenticate((X509Certificate[]) null);
        Assert.assertNull(p);
    }
}

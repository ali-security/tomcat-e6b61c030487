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
package org.apache.catalina.realm;

import java.net.InetAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

import org.apache.juli.logging.LogFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * When the JNDI realm validates the user provided credentials by binding as the user (no userPassword attribute
 * configured) it must always use a simple bind, regardless of the authentication mechanism configured for the
 * realm's own connection. Otherwise, a mechanism such as "none" (anonymous) ignores the provided password and any
 * password is accepted.
 */
@RunWith(Parameterized.class)
public class TestJNDIRealmBindAsUser {

    private static final String USER_PATTERN = "cn={0},ou=people,dc=example,dc=com";
    private static final String USER = "test";
    private static final String PASSWORD = "test";
    private static final String WRONG_PASSWORD = "not-the-password";

    private static InMemoryDirectoryServer ldapServer;

    @Parameterized.Parameters(name = "{index}: authentication[{0}], poolSize[{1}]")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        for (String authentication : new String[] { null, "none", "simple" }) {
            parameterSets.add(new Object[] { authentication, Integer.valueOf(1) });
            parameterSets.add(new Object[] { authentication, Integer.valueOf(2) });
        }
        return parameterSets;
    }

    @Parameter(0)
    public String authentication;
    @Parameter(1)
    public int poolSize;


    @Test
    public void testValidPassword() throws Exception {
        JNDIRealm realm = createRealm();
        // Repeat to check the configured authentication mechanism is correctly restored after each bind
        for (int i = 0; i < 3; i++) {
            Principal p = realm.authenticate(USER, PASSWORD);
            Assert.assertNotNull(p);
            Assert.assertEquals(USER, p.getName());
        }
    }


    @Test
    public void testInvalidPassword() throws Exception {
        JNDIRealm realm = createRealm();
        for (int i = 0; i < 3; i++) {
            Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
            // A valid login on the same connection must still work
            Assert.assertNotNull(realm.authenticate(USER, PASSWORD));
        }
    }


    @Test
    public void testEmptyPassword() throws Exception {
        JNDIRealm realm = createRealm();
        Assert.assertNull(realm.authenticate(USER, ""));
    }


    private JNDIRealm createRealm() {
        JNDIRealm realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealmBindAsUser.class);

        realm.setConnectionURL("ldap://localhost:" + ldapServer.getListenPort());
        realm.setAuthentication(authentication);
        realm.setUserPattern(USER_PATTERN);
        realm.setConnectionPoolSize(poolSize);
        return realm;
    }


    @BeforeClass
    public static void createLDAP() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        InetAddress localhost = InetAddress.getByName("localhost");
        InMemoryListenerConfig listenerConfig =
                new InMemoryListenerConfig("localListener", localhost, 0, null, null, null);
        config.setListenerConfigs(listenerConfig);
        ldapServer = new InMemoryDirectoryServer(config);

        ldapServer.startListening();

        try (LDAPConnection conn = ldapServer.getConnection()) {

            AddRequest addBase = new AddRequest(
                    "dn: dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: domain",
                    "dc: example");
            LDAPResult result = conn.processOperation(addBase);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addPeople = new AddRequest(
                    "dn: ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: organizationalUnit");
            result = conn.processOperation(addPeople);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addUserTest = new AddRequest(
                    "dn: cn=test,ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: person",
                    "objectClass: organizationalPerson",
                    "cn: test",
                    "sn: Test",
                    "userPassword: " + PASSWORD);
            result = conn.processOperation(addUserTest);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());
        }
    }


    @AfterClass
    public static void destroyLDAP() {
        ldapServer.shutDown(true);
    }
}

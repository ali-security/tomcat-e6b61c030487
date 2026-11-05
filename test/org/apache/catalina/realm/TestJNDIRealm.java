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

import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Hashtable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsInstanceOf.instanceOf;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.juli.logging.LogFactory;
import org.apache.naming.NameParserImpl;
import org.apache.tomcat.unittest.TesterContext;
import org.apache.tomcat.util.buf.HexUtils;
import org.easymock.EasyMock;

public class TestJNDIRealm {

    private static final String ALGORITHM = "MD5";

    private static final String USER = "test-user";
    private static final String PASSWORD = "test-password";
    private static final String REALM = "test-realm";
    private static final String USER_DN = "cn=test-user,ou=people,dc=example,dc=com";

    private static final String NONCE = "test-nonce";
    // Not digested but doesn't matter for the purposes of the test
    private static final String DIGEST_A2 = "method:request-uri";
    public static final String USER_PASSWORD_ATTR = "test-pwd";

    private static MessageDigest md5Helper;

    @BeforeClass
    public static void setupClass() throws Exception {
        md5Helper = MessageDigest.getInstance(ALGORITHM);
    }

    @Test
    public void testAuthenticateWithoutUserPassword() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(PASSWORD);

        // WHEN
        String expectedResponse =
                HexUtils.toHexString(md5Helper.digest((digestA1() + ":" + NONCE + ":" + DIGEST_A2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, DIGEST_A2, ALGORITHM);

        // THEN
        Assert.assertNull(principal);
    }

    @Test
    public void testAuthenticateWithUserPassword() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(PASSWORD);
        realm.setUserPassword(USER_PASSWORD_ATTR);

        // WHEN
        String expectedResponse =
                HexUtils.toHexString(md5Helper.digest((digestA1() + ":" + NONCE + ":" + DIGEST_A2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, DIGEST_A2, ALGORITHM);

        // THEN
        assertThat(principal, instanceOf(GenericPrincipal.class));
        Assert.assertEquals(USER, principal.getName());
    }

    @Test
    public void testAuthenticateWithUserPasswordAndCredentialHandler() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(digestA1());
        realm.setCredentialHandler(buildCredentialHandler());
        realm.setUserPassword(USER_PASSWORD_ATTR);

        // WHEN
        String expectedResponse =
                HexUtils.toHexString(md5Helper.digest((digestA1() + ":" + NONCE + ":" + DIGEST_A2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, DIGEST_A2, ALGORITHM);

        // THEN
        assertThat(principal, instanceOf(GenericPrincipal.class));
        Assert.assertEquals(USER, principal.getName());
    }

    @Test
    public void testErrorRealm() throws Exception {
        Context context = new TesterContext();
        JNDIRealm realm = new JNDIRealm();
        realm.setContainer(context);
        realm.setUserSearch("");
        // Connect to something that will fail
        realm.setConnectionURL("ldap://127.0.0.1:12345");
        realm.start();

        final CountDownLatch latch = new CountDownLatch(3);
        (new Thread(() -> { realm.authenticate("foo", "bar"); latch.countDown(); })).start();
        (new Thread(() -> { realm.authenticate("foo", "bar"); latch.countDown(); })).start();
        (new Thread(() -> { realm.authenticate("foo", "bar"); latch.countDown(); })).start();

        Assert.assertTrue(latch.await(30, TimeUnit.SECONDS));
    }


    @Test
    public void testBindAsUserAuthenticationDefault() throws Exception {
        doTestBindAsUser(null);
    }


    @Test
    public void testBindAsUserAuthenticationSimple() throws Exception {
        doTestBindAsUser("simple");
    }


    @Test
    public void testBindAsUserAuthenticationNone() throws Exception {
        doTestBindAsUser("none");
    }


    @Test
    public void testBindAsUserAuthenticationExternal() throws Exception {
        doTestBindAsUser("EXTERNAL");
    }


    @Test
    public void testBindAsUserAuthenticationGssapi() throws Exception {
        doTestBindAsUser("GSSAPI");
    }


    /*
     * Whatever authentication mechanism is configured for the realm's connection, the user provided credentials must
     * be validated with a simple bind and the configured mechanism must be restored afterwards.
     */
    private void doTestBindAsUser(String configuredMechanism) throws Exception {
        JNDIRealm realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealm.class);
        JNDIRealm.User user = new JNDIRealm.User(USER, USER_DN, null, null, null);

        BindRecordingDirContext context = new BindRecordingDirContext(configuredMechanism);
        Hashtable<?,?> originalEnvironment = context.getEnvironment();

        // Wrong password must be rejected
        Assert.assertFalse(realm.bindAsUser(context, user, "wrong-password"));
        Assert.assertEquals("simple", context.mechanismUsedForBind);
        Assert.assertEquals(originalEnvironment, context.getEnvironment());

        // Correct password must be accepted
        Assert.assertTrue(realm.bindAsUser(context, user, PASSWORD));
        Assert.assertEquals("simple", context.mechanismUsedForBind);
        Assert.assertEquals(originalEnvironment, context.getEnvironment());
    }


    private JNDIRealm buildRealm(String password) throws NamingException,
            NoSuchFieldException, IllegalAccessException, LifecycleException {
        Context context = new TesterContext();
        JNDIRealm realm = new JNDIRealm();
        realm.setContainer(context);
        realm.setUserSearch("");

        // Usually everything is created in create() but that's not the case here
        Field field = JNDIRealm.class.getDeclaredField("singleConnection");
        field.setAccessible(true);
        Field field2 = JNDIRealm.JNDIConnection.class.getDeclaredField("context");
        field2.setAccessible(true);
        field2.set(field.get(realm), mockDirContext(mockSearchResults(password)));

        realm.start();

        return realm;
    }

    private MessageDigestCredentialHandler buildCredentialHandler()
            throws NoSuchAlgorithmException {
        MessageDigestCredentialHandler credentialHandler = new MessageDigestCredentialHandler();
        credentialHandler.setAlgorithm(ALGORITHM);
        return credentialHandler;
    }

    private NamingEnumeration<SearchResult> mockSearchResults(String password)
            throws NamingException {
        NamingEnumeration<SearchResult> searchResults =
                EasyMock.createNiceMock(NamingEnumeration.class);
        EasyMock.expect(Boolean.valueOf(searchResults.hasMore()))
                .andReturn(Boolean.TRUE)
                .andReturn(Boolean.FALSE)
                .andReturn(Boolean.TRUE)
                .andReturn(Boolean.FALSE);
        EasyMock.expect(searchResults.next())
                .andReturn(new SearchResult("ANY RESULT", "",
                        new BasicAttributes(USER_PASSWORD_ATTR, password)))
                .times(2);
        EasyMock.replay(searchResults);
        return searchResults;
    }

    private DirContext mockDirContext(NamingEnumeration<SearchResult> namingEnumeration)
            throws NamingException {
        DirContext dirContext = EasyMock.createNiceMock(InitialDirContext.class);
        EasyMock.expect(dirContext.search(EasyMock.anyString(), EasyMock.anyString(),
                        EasyMock.anyObject(SearchControls.class)))
                .andReturn(namingEnumeration)
                .times(2);
        EasyMock.expect(dirContext.getNameParser(""))
                .andReturn(new NameParserImpl()).times(2);
        EasyMock.expect(dirContext.getNameInNamespace())
                .andReturn("ANY NAME")
                .times(2);
        EasyMock.replay(dirContext);
        return dirContext;
    }

    private String digestA1() {
        String a1 = USER + ":" + REALM + ":" + PASSWORD;
        return HexUtils.toHexString(md5Helper.digest(a1.getBytes()));
    }


    /*
     * Minimal directory context that simulates the LDAP bind performed by a directory operation. A simple bind (also
     * the provider default when credentials are provided) checks the provided password. The other mechanisms ignore
     * the provided password: "none" is an anonymous bind while "EXTERNAL" and "GSSAPI" authenticate using an identity
     * established outside of the bind (e.g. TLS client certificate or Kerberos credentials).
     */
    private static class BindRecordingDirContext extends InitialDirContext {

        private final Hashtable<Object,Object> environment = new Hashtable<>();
        private String mechanismUsedForBind;

        BindRecordingDirContext(String configuredMechanism) throws NamingException {
            super(true);
            if (configuredMechanism != null) {
                environment.put(javax.naming.Context.SECURITY_AUTHENTICATION, configuredMechanism);
            }
        }

        @Override
        public Hashtable<?,?> getEnvironment() {
            return (Hashtable<?,?>) environment.clone();
        }

        @Override
        public Object addToEnvironment(String propName, Object propVal) {
            return environment.put(propName, propVal);
        }

        @Override
        public Object removeFromEnvironment(String propName) {
            return environment.remove(propName);
        }

        @Override
        public Attributes getAttributes(String name, String[] attrIds) throws NamingException {
            mechanismUsedForBind = (String) environment.get(javax.naming.Context.SECURITY_AUTHENTICATION);
            if (mechanismUsedForBind == null || "simple".equals(mechanismUsedForBind)) {
                if (!USER_DN.equals(environment.get(javax.naming.Context.SECURITY_PRINCIPAL)) ||
                        !PASSWORD.equals(environment.get(javax.naming.Context.SECURITY_CREDENTIALS))) {
                    throw new AuthenticationException("Invalid credentials");
                }
            }
            return new BasicAttributes();
        }
    }
}

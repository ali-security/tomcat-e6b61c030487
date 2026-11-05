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
package org.apache.catalina.authenticator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.DigestAuthenticator.AuthDigest;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

@RunWith(Parameterized.class)
public class TestDigestAuthenticatorB extends TomcatBaseTest {

    private static final String validRole = "role";
    private static final String validUser = "user";
    private static final String validPassword = "password";

    private static final String targetURI = "/protected";
    private static final String realmName = "TestRealm";
    private static final String clientNonce = "cnonce";

    @Parameterized.Parameters(name = "{index}: role[{0}], user[{1}], pwd[{2}], valid[{3}]")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        parameterSets.add(new Object[] { validRole, validUser, validPassword, Boolean.TRUE });
        parameterSets.add(new Object[] { validRole, validUser, "wrongpassword", Boolean.FALSE });
        parameterSets.add(new Object[] { validRole, "invalid", "null", Boolean.FALSE });
        /*
         * The "**" role grants access to any authenticated user so there is no authorization step to mask a failure of
         * the authentication step. A user that does not exist in the Realm must not be able to authenticate by
         * presenting the digest of the literal String "null" as the password.
         */
        parameterSets.add(new Object[] { SecurityConstraint.ROLE_ALL_AUTHENTICATED_USERS, validUser, validPassword,
                Boolean.TRUE });
        parameterSets.add(
                new Object[] { SecurityConstraint.ROLE_ALL_AUTHENTICATED_USERS, "invalid", "null", Boolean.FALSE });
        return parameterSets;
    }

    @Parameter(0)
    public String role;

    @Parameter(1)
    public String clientUserName;

    @Parameter(2)
    public String clientPassword;

    @Parameter(3)
    public boolean validCredentials;


    @Test
    public void testDigestAuthentication() throws Exception {

        Tomcat tomcat = getTomcatInstance();

        // No file system docBase required
        Context ctxt = tomcat.addContext("", null);

        // Add protected servlet
        Tomcat.addServlet(ctxt, "TesterServlet", new TesterServlet());
        ctxt.addServletMappingDecoded(targetURI, "TesterServlet");
        SecurityCollection collection = new SecurityCollection();
        collection.addPatternDecoded(targetURI);
        SecurityConstraint sc = new SecurityConstraint();
        // Required for the "**" role as addAuthRole() only sets this for named roles
        sc.setAuthConstraint(true);
        sc.addAuthRole(role);
        sc.addCollection(collection);
        ctxt.addConstraint(sc);

        // Configure the Realm
        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser(validUser, validPassword);
        realm.addUserRole(validUser, validRole);
        ctxt.setRealm(realm);

        // Configure the authenticator
        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod("DIGEST");
        lc.setRealmName(realmName);
        ctxt.setLoginConfig(lc);
        DigestAuthenticator digestAuthenticator = new DigestAuthenticator();
        digestAuthenticator.setAlgorithms("SHA-256");
        ctxt.getPipeline().addValve(digestAuthenticator);

        tomcat.start();

        // First request will always fail - but we need the challenge
        Map<String,List<String>> respHeaders = new HashMap<>();
        ByteChunk bc = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + targetURI, bc, respHeaders);
        Assert.assertEquals(401, rc);
        Assert.assertTrue(bc.getLength() > 0);
        bc.recycle();

        // Second request should only succeed if the credentials are valid
        List<String> auth = new ArrayList<>();
        auth.add(TestDigestAuthenticatorAlgorithms.buildDigestResponse(clientUserName, clientPassword, targetURI,
                realmName, AuthDigest.SHA_256, respHeaders.get(AuthenticatorBase.AUTH_HEADER_NAME), "00000001",
                clientNonce, DigestAuthenticator.QOP));
        Map<String,List<String>> reqHeaders = new HashMap<>();
        reqHeaders.put("authorization", auth);
        rc = getUrl("http://localhost:" + getPort() + targetURI, bc, reqHeaders, null);

        if (validCredentials) {
            Assert.assertEquals(200, rc);
            Assert.assertEquals("OK", bc.toString());
        } else {
            Assert.assertEquals(401, rc);
        }
    }
}

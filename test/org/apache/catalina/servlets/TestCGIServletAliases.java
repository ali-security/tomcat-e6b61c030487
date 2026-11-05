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
package org.apache.catalina.servlets;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.compat.JrePlatform;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/*
 * CVE-2025-46701. The CGI servlet must locate scripts via the web application's
 * resources (WebResourceRoot) rather than via the file system directly so that
 * a request path that is merely an alias for a protected script (a different
 * case on a case insensitive file system, a symbolic link, etc.) is not able to
 * bypass the security constraints configured for that script.
 */
public class TestCGIServletAliases extends TomcatBaseTest {

    private static final String CGI_PREFIX = "WEB-INF/cgi";
    private static final String CGI_MAPPING = "/cgi-bin/*";
    private static final String ROLE = "admin";

    @Test
    public void testPublicScript() throws Exception {
        Assume.assumeFalse("Test requires /bin/sh", JrePlatform.IS_WINDOWS);
        File cgiDir = setUpWebApp();
        Assert.assertTrue(new File(cgiDir, "public.sh").isFile());

        ByteChunk out = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/public.sh", out, null);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
        Assert.assertEquals("PUBLIC", out.toString().trim());
    }


    @Test
    public void testPublicScriptWithPathInfo() throws Exception {
        Assume.assumeFalse("Test requires /bin/sh", JrePlatform.IS_WINDOWS);
        setUpWebApp();

        ByteChunk out = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/public.sh/extra/path", out, null);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
        Assert.assertEquals("PUBLIC", out.toString().trim());
    }


    @Test
    public void testMissingScript() throws Exception {
        setUpWebApp();

        ByteChunk out = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/missing.sh", out, null);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
    }


    @Test
    public void testProtectedScriptRequiresAuthentication() throws Exception {
        setUpWebApp();

        ByteChunk out = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/secret.sh", out, null);

        Assert.assertEquals(HttpServletResponse.SC_UNAUTHORIZED, rc);
        Assert.assertFalse(out.toString().contains("SECRET"));
    }


    /*
     * The attack described by CVE-2025-46701. On a case insensitive file
     * system the case-variant request path is not covered by the security
     * constraint but File based lookups would still resolve it to the protected
     * script.
     */
    @Test
    public void testCaseVariantDoesNotBypassConstraint() throws Exception {
        setUpWebApp();

        ByteChunk out = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/SECRET.sh", out, null);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
        Assert.assertFalse(out.toString().contains("SECRET"));
    }


    /*
     * Same attack as above but using an alias that can be created on a case
     * sensitive file system. The resources implementation rejects aliases (case
     * differences and symbolic links) via the same canonical path check so this
     * test demonstrates that the CGI servlet no longer bypasses that check.
     */
    @Test
    public void testSymbolicLinkDoesNotBypassConstraint() throws Exception {
        File cgiDir = setUpWebApp();

        Path alias = new File(cgiDir, "alias.sh").toPath();
        try {
            Files.createSymbolicLink(alias, new File(cgiDir, "secret.sh").toPath());
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            Assume.assumeNoException("Unable to create symbolic link", e);
        }
        Assert.assertTrue(alias.toFile().isFile());

        ByteChunk out = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/cgi-bin/alias.sh", out, null);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
        Assert.assertFalse(out.toString().contains("SECRET"));
    }


    private File setUpWebApp() throws Exception {
        File appDir = new File(getTemporaryDirectory(), "cgi-app");
        File cgiDir = new File(appDir, CGI_PREFIX);
        Assert.assertTrue(cgiDir.mkdirs() || cgiDir.isDirectory());
        addDeleteOnTearDown(appDir);

        writeScript(new File(cgiDir, "public.sh"), "PUBLIC");
        writeScript(new File(cgiDir, "secret.sh"), "SECRET");

        Tomcat tomcat = getTomcatInstance();
        Context ctx = tomcat.addContext("", appDir.getAbsolutePath());

        Wrapper wrapper = Tomcat.addServlet(ctx, "cgi", new CGIServlet());
        wrapper.addInitParameter("cgiPathPrefix", CGI_PREFIX);
        wrapper.addInitParameter("executable", "/bin/sh");
        ctx.addServletMappingDecoded(CGI_MAPPING, "cgi");

        // Protect the secret script
        SecurityCollection collection = new SecurityCollection();
        collection.addPatternDecoded("/cgi-bin/secret.sh");
        SecurityConstraint constraint = new SecurityConstraint();
        constraint.addAuthRole(ROLE);
        constraint.addCollection(collection);
        ctx.addConstraint(constraint);

        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser("user", "pwd");
        realm.addUserRole("user", ROLE);
        ctx.setRealm(realm);

        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod(HttpServletRequest.BASIC_AUTH);
        ctx.setLoginConfig(lc);
        ctx.getPipeline().addValve(new BasicAuthenticator());

        tomcat.start();

        return cgiDir;
    }


    private static void writeScript(File script, String output) throws IOException {
        String content = "echo 'Content-Type: text/plain'\n" + "echo ''\n" + "echo '" + output + "'\n";
        Files.write(script.toPath(), content.getBytes(StandardCharsets.US_ASCII));
    }
}

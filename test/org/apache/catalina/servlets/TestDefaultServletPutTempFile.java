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
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.ReadListener;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.ExpandWar;
import org.apache.catalina.startup.SimpleHttpClient;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests for the temporary files used by partial PUT (CVE-2025-24813).
 * <p>
 * The original implementation derived the name of the temporary file from the user provided path by replacing the path
 * separator with '.'. That made the name of the temporary file both predictable and subject to collisions between
 * different resource paths.
 */
public class TestDefaultServletPutTempFile extends TomcatBaseTest {

    private static final String CRLF = SimpleHttpClient.CRLF;

    private static final String SECRET = "TOP-SECRET-PASSWORD-0123456789";

    private File tempDocBase;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        tempDocBase = Files.createTempDirectory(getTemporaryDirectory().toPath(), "put").toFile();
    }


    @Override
    public void tearDown() throws Exception {
        try {
            super.tearDown();
        } finally {
            ExpandWar.deleteDir(tempDocBase, false);
        }
    }


    /*
     * The published exploit for CVE-2025-24813. A partial PUT of "/1.session" wrote the request body to
     * "<TEMPDIR>/.1.session" which is exactly where Tomcat's file based session persistence looks for the session with
     * the ID ".1". Combined with a library that can be leveraged in a deserialization attack that provides remote code
     * execution.
     */
    @Test
    public void testPartialPutDoesNotCreateAttackerNamedTempFile() throws Exception {
        Context ctxt = startTomcat(new DefaultServlet());
        File tempDir = getTempDir(ctxt);
        Set<String> before = list(tempDir);

        String body = "SERIALIZED-GADGET-CHAIN";

        PutClient client = new PutClient(getPort());
        client.setRequest(new String[] { "PUT /1.session HTTP/1.1" + CRLF + "Host: localhost:" + getPort() + CRLF +
                "Content-Range: bytes 0-" + (body.length() - 1) + "/" + body.length() + CRLF + "Content-Length: " +
                body.length() + CRLF + CRLF + body });
        client.connect();
        client.processRequest(false);
        client.disconnect();

        File sessionFile = new File(tempDir, ".1.session");
        Assert.assertFalse(
                "CVE-2025-24813: partial PUT created the attacker named temporary file [" +
                        sessionFile.getAbsolutePath() + "]",
                sessionFile.exists());
        Assert.assertEquals("CVE-2025-24813: partial PUT left a temporary file behind", before, list(tempDir));
    }


    /*
     * The information disclosure / content injection variant of CVE-2025-24813. Because the name of the temporary file
     * was "path.replace('/', '.')", the sensitive resource "/pub/secret/x.txt" and the public resource
     * "/pub/secret.x.txt" shared a single temporary file. The attacker therefore obtained the content of the sensitive
     * resource via a partial PUT of the public resource (and could equally have injected content into the sensitive
     * resource).
     */
    @Test
    public void testPartialPutTempFileIsNotSharedBetweenPaths() throws Exception {
        Assert.assertTrue(new File(tempDocBase, "pub" + File.separator + "secret").mkdirs());

        Context ctxt = startTomcat(new DefaultServlet());
        File tempDir = getTempDir(ctxt);
        Set<String> before = list(tempDir);

        int secretLen = SECRET.length();

        // Victim uploads a security sensitive file using a partial PUT.
        PutClient client = new PutClient(getPort());
        client.setRequest(new String[] { "PUT /pub/secret/x.txt HTTP/1.1" + CRLF + "Host: localhost:" + getPort() +
                CRLF + "Content-Range: bytes 0-" + (secretLen - 1) + "/" + secretLen + CRLF + "Content-Length: " +
                secretLen + CRLF + CRLF + SECRET });
        client.connect();
        client.processRequest(false);
        Assert.assertTrue(client.isResponse201());
        client.disconnect();

        // Attacker uploads a public file that used to map to the same temporary file.
        client.reset();
        client.connect();
        client.setRequest(new String[] { "PUT /pub/secret.x.txt HTTP/1.1" + CRLF + "Host: localhost:" + getPort() +
                CRLF + "Content-Range: bytes " + secretLen + "-" + secretLen + "/" + (secretLen + 1) + CRLF +
                "Content-Length: 1" + CRLF + CRLF + "!" });
        client.processRequest(false);
        client.disconnect();

        // Attacker reads back the public file.
        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/pub/secret.x.txt", responseBody, null);
        Assert.assertEquals(200, rc);
        Assert.assertFalse(
                "CVE-2025-24813: the content of [/pub/secret/x.txt] leaked via [/pub/secret.x.txt]",
                responseBody.toString().contains(SECRET));

        // The sensitive resource must still hold the content the victim uploaded.
        responseBody.recycle();
        rc = getUrl("http://localhost:" + getPort() + "/pub/secret/x.txt", responseBody, null);
        Assert.assertEquals(200, rc);
        Assert.assertEquals(SECRET, responseBody.toString());

        Assert.assertEquals("CVE-2025-24813: partial PUT left a temporary file behind", before, list(tempDir));
    }


    /*
     * A partial PUT that fails part way through must not leave the partially written temporary file on disk.
     */
    @Test
    public void testPartialPutTempFileRemovedWhenRequestFails() throws Exception {
        Context ctxt = startTomcat(new FailingReadDefaultServlet());
        File tempDir = getTempDir(ctxt);
        Set<String> before = list(tempDir);

        PutClient client = new PutClient(getPort());
        client.setRequest(new String[] { "PUT /abort.txt HTTP/1.1" + CRLF + "Host: localhost:" + getPort() + CRLF +
                "Content-Range: bytes 0-9/10" + CRLF + "Content-Length: 10" + CRLF + CRLF + "0123456789" });
        client.connect();
        client.processRequest(false);
        client.disconnect();

        Assert.assertEquals("CVE-2025-24813: a failed partial PUT left a temporary file behind", before,
                list(tempDir));
    }


    private Context startTomcat(Servlet servlet) throws Exception {
        Tomcat tomcat = getTomcatInstance();
        Context ctxt = tomcat.addContext("", tempDocBase.getAbsolutePath());

        Wrapper w = Tomcat.addServlet(ctxt, "default", servlet);
        w.addInitParameter("readonly", "false");
        w.addInitParameter("allowPartialPut", "true");
        ctxt.addServletMappingDecoded("/", "default");

        tomcat.start();

        // Disable caching
        ctxt.getResources().setCachingAllowed(false);

        return ctxt;
    }


    private static File getTempDir(Context ctxt) {
        return (File) ctxt.getServletContext().getAttribute(ServletContext.TEMPDIR);
    }


    private static Set<String> list(File dir) {
        Set<String> result = new HashSet<>();
        String[] names = dir.list();
        if (names != null) {
            Collections.addAll(result, names);
        }
        return result;
    }


    /**
     * A DefaultServlet where reading the request body of a PUT always fails.
     */
    public static class FailingReadDefaultServlet extends DefaultServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPut(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            HttpServletRequest wrapped = new HttpServletRequestWrapper(req) {
                @Override
                public ServletInputStream getInputStream() throws IOException {
                    return new FailingServletInputStream();
                }
            };
            try {
                super.doPut(wrapped, resp);
            } catch (IOException e) {
                // Expected. Report it rather than letting the container handle it.
                resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }
    }


    private static class FailingServletInputStream extends ServletInputStream {

        @Override
        public int read() throws IOException {
            throw new IOException("Simulated read failure");
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            throw new IOException("Simulated read failure");
        }

        @Override
        public boolean isFinished() {
            return false;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            // NO-OP
        }
    }


    private static class PutClient extends SimpleHttpClient {

        PutClient(int port) {
            setPort(port);
        }


        @Override
        public boolean isResponseBodyOK() {
            return false;
        }
    }
}

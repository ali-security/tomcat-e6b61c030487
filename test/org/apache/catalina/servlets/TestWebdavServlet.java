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
import java.io.StringReader;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.SAXParserFactory;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.SimpleHttpClient;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.websocket.server.WsContextListener;
import org.xml.sax.InputSource;

public class TestWebdavServlet extends TomcatBaseTest {

    private static final String CRLF = SimpleHttpClient.CRLF;

    private static final String LOCK_BODY = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>" + CRLF +
                                            "<D:lockinfo xmlns:D='DAV:'>" + CRLF +
                                            "  <D:lockscope><D:exclusive/></D:lockscope>" + CRLF +
                                            "  <D:locktype><D:write/></D:locktype>" + CRLF +
                                            "  <D:owner>" + CRLF +
                                            "    <D:href>http://www.apache.org</D:href>" + CRLF +
                                            "  </D:owner>" + CRLF +
                                            "</D:lockinfo>";

    private static final String PROPFIND_PROP = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>" + CRLF +
                                                "<D:propfind xmlns:D='DAV:'>" + CRLF +
                                                "  <D:prop>" + CRLF +
                                                "    <D:getcontentlength/>" + CRLF +
                                                "    <D:getlastmodified/>" + CRLF +
                                                "  </D:prop>" + CRLF +
                                                "</D:propfind>";


    /*
     * Test attempting to access special paths (WEB-INF/META-INF) using WebdavServlet
     */
    @Test
    public void testGetSpecials() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        String contextPath = "/examples";

        File appDir = new File(getBuildDirectory(), "webapps" + contextPath);
        // app dir is relative to server home
        Context ctx = tomcat.addWebapp(null, "/examples", appDir.getAbsolutePath());

        Tomcat.addServlet(ctx, "webdav", new WebdavServlet());
        ctx.addServletMappingDecoded("/*", "webdav");

        tomcat.start();

        final ByteChunk res = new ByteChunk();

        int rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/WEB-INF/web.xml", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/WEB-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/WEB-INF/", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/META-INF/MANIFEST.MF", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/META-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

    }

    /*
     * Test https://bz.apache.org/bugzilla/show_bug.cgi?id=50026
     * Verify protection of special paths with re-mount of web app resource root.
     */
    @Test
    public void testGetWithSubpathmount() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        String contextPath = "/examples";

        File appDir = new File(getBuildDirectory(), "webapps" + contextPath);
        // app dir is relative to server home
        Context ctx = tomcat.addWebapp(null, "/examples", appDir.getAbsolutePath());

        Tomcat.addServlet(ctx, "webdav", new WebdavServlet());
        ctx.addServletMappingDecoded("/webdav/*", "webdav");
        ctx.addApplicationListener(WsContextListener.class.getName());

        tomcat.start();

        final ByteChunk res = new ByteChunk();

        // Make sure WebdavServlet isn't exposing special directories
        // by remounting the webapp under a sub-path

        int rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/WEB-INF/web.xml", res, null);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/WEB-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/WEB-INF/", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/META-INF/MANIFEST.MF", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/META-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        // Make sure WebdavServlet is serving resources
        // relative to the map/mount point
        final ByteChunk rootResource = new ByteChunk();
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/index.html", rootResource, null);
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        final ByteChunk subpathResource = new ByteChunk();
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/index.html", subpathResource, null);
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        Assert.assertEquals(rootResource.toString(), subpathResource.toString());

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/static/index.html", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

    }

    public static int getUrl(String path, ByteChunk out,
            Map<String, List<String>> resHead) throws IOException {
        out.recycle();
        return TomcatBaseTest.getUrl(path, out, resHead);
    }

    /*
     * Bug 66609
     */
    @Test
    public void testDirectoryListing() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        File appDir = new File("test/webapp");
        Context ctxt = tomcat.addContext("", appDir.getAbsolutePath());

        Wrapper defaultServlet = Tomcat.addServlet(ctxt, "webdav", new WebdavServlet());
        defaultServlet.addInitParameter("listings", "true");

        ctxt.addServletMappingDecoded("/*", "webdav");
        ctxt.addMimeMapping("html", "text/html");

        tomcat.start();

        Client client = new Client();
        client.setPort(getPort());
        client.setRequest(new String[] { "PROPFIND /bug66609/ HTTP/1.1" + SimpleHttpClient.CRLF +
                                         "Host: localhost:" + getPort() + SimpleHttpClient.CRLF +
                                         SimpleHttpClient.CRLF});
        client.connect();
        client.sendRequest();

        client.setUseContentLength(true);
        client.readResponse(true);

        // This will throw an exception if the XML is not valid
        SAXParserFactory.newInstance().newSAXParser().getXMLReader().parse(new InputSource(new StringReader(client.getResponseBody())));
    }


    /*
     * Only tests LOCK bodies exceeding limit. Other tests cover valid LOCK bodies.
     */
    @Test
    public void testLockBodyLimit() throws Exception {
        doTestLimit("LOCK", "/", LOCK_BODY, true, true);
    }


    /*
     * As above but using chunked encoding so no content length is available and the limit has to be enforced while the
     * request body is being read.
     */
    @Test
    public void testLockBodyLimitChunked() throws Exception {
        doTestLimit("LOCK", "/", LOCK_BODY, false, true);
    }


    /*
     * Only tests PROPFIND bodies exceeding limit. Other tests cover valid PROPFIND bodies.
     */
    @Test
    public void testPropFindBodyLimit() throws Exception {
        doTestLimit("PROPFIND", "/", PROPFIND_PROP, true, true);
    }


    /*
     * As above but using chunked encoding so no content length is available and the limit has to be enforced while the
     * request body is being read.
     */
    @Test
    public void testPropFindBodyLimitChunked() throws Exception {
        doTestLimit("PROPFIND", "/", PROPFIND_PROP, false, true);
    }


    /*
     * Only tests MKCOL bodies exceeding limit. A MKCOL request body is only read when the client provides a content
     * length so the chunked case is not tested.
     */
    @Test
    public void testMkColBodyLimit() throws Exception {
        doTestLimit("MKCOL", "/newcollection/", PROPFIND_PROP, true, false);
    }


    private void doTestLimit(String method, String path, String requestBody, boolean testContentLength,
            boolean testChunked) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        File appDir = new File("test/webapp");
        Context ctxt = tomcat.addContext("", appDir.getAbsolutePath());

        Wrapper webdavServlet = Tomcat.addServlet(ctxt, "webdav", new WebdavServlet());
        webdavServlet.addInitParameter("listings", "true");
        webdavServlet.addInitParameter("secret", "foo");
        webdavServlet.addInitParameter("readonly", "false");
        webdavServlet.addInitParameter("maxRequestBodySize", "10");

        ctxt.addServletMappingDecoded("/*", "webdav");
        tomcat.start();

        if (testContentLength) {
            // With content length
            Client client = new Client();
            client.setPort(getPort());

            // @formatter:off
            client.setRequest(new String[] {
                    method + " " + path + " HTTP/1.1" + CRLF +
                        "Host: localhost:" + getPort() + CRLF +
                        "Content-Length: " + requestBody.length() + CRLF +
                        "Connection: Close" + CRLF +
                        CRLF +
                        requestBody
                    });
            // @formatter:on
            client.connect();
            client.processRequest(true);
            Assert.assertEquals("With content length: " + client.getResponseLine(),
                    WebdavStatus.SC_REQUEST_TOO_LONG, client.getStatusCode());
            client.disconnect();
        }

        if (testChunked) {
            // Without content length
            Client client = new Client();
            client.setPort(getPort());

            // @formatter:off
            client.setRequest(new String[] {
                    method + " " + path + " HTTP/1.1" + CRLF +
                        "Host: localhost:" + getPort() + CRLF +
                        "Transfer-Encoding: chunked" + CRLF +
                        "Connection: Close" + CRLF +
                        CRLF +
                        Integer.toHexString(requestBody.length()) + CRLF +
                        requestBody + CRLF +
                        "0" + CRLF +
                        CRLF
                    });
            // @formatter:on
            client.connect();
            client.processRequest(true);
            Assert.assertEquals("Without content length: " + client.getResponseLine(),
                    WebdavStatus.SC_REQUEST_TOO_LONG, client.getStatusCode());
            client.disconnect();
        }
    }


    private static final class Client extends SimpleHttpClient {

        @Override
        public boolean isResponseBodyOK() {
            return true;
        }

        /*
         * SimpleHttpClient in this version does not expose the numeric status code.
         */
        public int getStatusCode() {
            String responseLine = getResponseLine();
            Assert.assertNotNull("No response line", responseLine);
            // Response line format is "HTTP/1.1 nnn [reason phrase]"
            return Integer.parseInt(responseLine.substring(9, 12));
        }
    }
}

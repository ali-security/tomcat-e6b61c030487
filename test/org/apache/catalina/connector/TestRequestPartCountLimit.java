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
package org.apache.catalina.connector;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.MultipartConfigElement;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests the enforcement of {@link Connector#getMaxPartCount()} and
 * {@link Connector#getMaxPartHeaderSize()} for multipart/form-data requests
 * (CVE-2025-48988).
 *
 * The part count limit is deliberately exercised with maxParameterCount set to
 * -1 (unlimited) so that it is maxPartCount, and not the parameter based limit,
 * that has to reject a request with an unbounded number of parts.
 */
public class TestRequestPartCountLimit extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "partCountLimitBoundary";

    private static final int MAX_PART_COUNT = 3;


    /*
     * A request whose part count exceeds maxPartCount must be rejected, even
     * when the parameter based limit is disabled (maxParameterCount == -1). The
     * FileUpload layer surfaces this as a FileCountLimitExceededException which
     * the container reports from getParts() as an IOException.
     */
    @Test
    public void testPartCountExceedsMaxPartCount() throws Exception {
        String response = doTestUpload(MAX_PART_COUNT, MAX_PART_COUNT + 2);
        Assert.assertEquals("RESULT:FileCountLimitExceededException:published=0", response);
    }


    /*
     * A request whose part count is within maxPartCount must still be accepted
     * and exposed to the application. This confirms the limit is non-breaking
     * for legitimate multipart requests.
     */
    @Test
    public void testPartCountWithinMaxPartCount() throws Exception {
        String response = doTestUpload(MAX_PART_COUNT, MAX_PART_COUNT);
        Assert.assertEquals("RESULT:parts=" + MAX_PART_COUNT + ":published=" + MAX_PART_COUNT, response);
    }


    /*
     * A part whose headers exceed maxPartHeaderSize must be rejected. The
     * FileUpload layer raises a SizeLimitExceededException which the container
     * reports from getParts() as an IllegalStateException.
     */
    @Test
    public void testPartHeaderExceedsMaxPartHeaderSize() throws Exception {
        String response = doTestUpload(MAX_PART_COUNT, 1, 256, 300);
        Assert.assertEquals("RESULT:IllegalStateException:SizeLimitExceededException:published=0", response);
    }


    /*
     * Part headers within maxPartHeaderSize must still be accepted.
     */
    @Test
    public void testPartHeaderWithinMaxPartHeaderSize() throws Exception {
        String response = doTestUpload(MAX_PART_COUNT, 1, 256, 10);
        Assert.assertEquals("RESULT:parts=1:published=1", response);
    }


    /*
     * The default maxPartHeaderSize is the fixed limit that applied before it
     * was configurable, so part headers accepted before are still accepted.
     */
    @Test
    public void testDefaultMaxPartHeaderSize() throws Exception {
        Assert.assertEquals(10240, new Connector().getMaxPartHeaderSize());
        String response = doTestUpload(MAX_PART_COUNT, 1, null, 9000);
        Assert.assertEquals("RESULT:parts=1:published=1", response);
    }


    private String doTestUpload(int maxPartCount, int partCount) throws Exception {
        return doTestUpload(maxPartCount, partCount, null, 0);
    }


    private String doTestUpload(int maxPartCount, int partCount, Integer maxPartHeaderSize, int headerPadding)
            throws Exception {

        Tomcat tomcat = getTomcatInstance();

        File uploadDir = new File(getTemporaryDirectory(),
                "test-part-count-" + maxPartCount + "-" + partCount + "-" + headerPadding);
        Assert.assertTrue(uploadDir.mkdirs());
        addDeleteOnTearDown(uploadDir);

        // No file system docBase required
        Context ctx = tomcat.addContext("", null);

        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        /*
         * Tomcat.addServlet() does not process annotations so the multi-part
         * configuration has to be set explicitly. There are deliberately no
         * FileUpload level size limits so that it is maxPartCount that has to
         * reject the request.
         */
        w.setMultipartConfigElement(new MultipartConfigElement(uploadDir.getAbsolutePath(), -1, -1, 1));
        ctx.addServletMappingDecoded("/", "parts");

        // Disable the parameter based limit so only maxPartCount can reject
        tomcat.getConnector().setMaxParameterCount(-1);
        tomcat.getConnector().setMaxPartCount(maxPartCount);
        if (maxPartHeaderSize != null) {
            tomcat.getConnector().setMaxPartHeaderSize(maxPartHeaderSize.intValue());
        }

        tomcat.start();

        StringBuilder body = new StringBuilder();
        for (int i = 0; i < partCount; i++) {
            body.append("--").append(BOUNDARY).append(CRLF);
            body.append("Content-Disposition: form-data; name=\"file").append(i)
                    .append("\"; filename=\"file").append(i).append(".txt\"").append(CRLF);
            body.append("Content-Type: text/plain").append(CRLF);
            if (headerPadding > 0) {
                body.append("X-Padding: ").append("p".repeat(headerPadding)).append(CRLF);
            }
            body.append(CRLF);
            body.append('X').append(CRLF);
        }
        body.append("--").append(BOUNDARY).append("--").append(CRLF);

        Map<String,List<String>> reqHeaders = new HashMap<>();
        reqHeaders.put("Content-Type", Arrays.asList("multipart/form-data; boundary=" + BOUNDARY));

        ByteChunk out = new ByteChunk();
        int rc = postUrl(body.toString().getBytes(StandardCharsets.ISO_8859_1),
                "http://localhost:" + getPort() + "/", out, reqHeaders, null);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        return out.toString();
    }


    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            String result;
            try {
                result = "parts=" + req.getParts().size();
            } catch (IOException ioe) {
                // A part count that exceeds maxPartCount surfaces here
                result = ioe.getClass().getSimpleName();
            } catch (IllegalStateException ise) {
                // Part headers that exceed maxPartHeaderSize surface here
                result = ise.getClass().getSimpleName() + ":" +
                        (ise.getCause() == null ? "" : ise.getCause().getClass().getSimpleName());
            }

            /*
             * The parts the container published on the internal request. A
             * request rejected for exceeding maxPartCount must publish none.
             */
            Collection<?> published = ((RequestFacade) req).request.parts;

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print("RESULT:" + result + ":published=" +
                    (published == null ? "0" : Integer.toString(published.size())));
        }
    }
}

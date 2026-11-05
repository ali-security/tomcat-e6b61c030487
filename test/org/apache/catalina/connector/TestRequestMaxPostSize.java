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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.Socket;
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
import jakarta.servlet.http.Part;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests the enforcement of {@link Connector#getMaxPostSize()} for the non-file
 * parts of a multipart request.
 */
public class TestRequestMaxPostSize extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "simpleMaxPostSizeBoundary";

    /*
     * The equivalent size of a non-file part is the length of its name, plus an
     * equals sign, plus the size of its value, plus a separator. FileUpload
     * reports the size of a part as a long. Accumulating the equivalent sizes
     * in an int meant that a part larger than Integer.MAX_VALUE wrapped that
     * total around to a negative value which then passed the maxPostSize check,
     * so the limit could be bypassed completely.
     */
    private static final long OVER_SIZED_PART = Integer.MAX_VALUE + 1024L;

    /*
     * Small, but above the file size threshold used below so that the part is
     * written to disk rather than kept in memory.
     */
    private static final int UPLOADED_PART_SIZE = 2048;

    private static final int MAX_POST_SIZE = 1024;


    /*
     * A part whose size on its own exceeds maxPostSize must be rejected even
     * when that size does not fit in a signed 32 bit int.
     *
     * A part that large cannot be uploaded by a test so a small part is
     * uploaded and the temporary file that backs it is then extended - which
     * creates a sparse file and therefore uses no disk space - while the parser
     * is blocked waiting for the remainder of the request. The size of a part
     * that has been written to disk is the length of that file, which is
     * exactly the value the size tracking in Request.parseParts() consumes.
     */
    @Test
    public void testMaxPostSizeExceededByOverSizedPart() throws Exception {

        Tomcat tomcat = getTomcatInstance();

        File uploadDir = new File(getTemporaryDirectory(), "test-max-post-size-over-sized-part");
        Assert.assertTrue(uploadDir.mkdirs());
        addDeleteOnTearDown(uploadDir);

        // No file system docBase required
        Context ctx = tomcat.addContext("", null);

        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        /*
         * Tomcat.addServlet() does not process annotations so the multi-part
         * configuration has to be set explicitly. There are deliberately no
         * FileUpload level limits so that it is maxPostSize that has to reject
         * the request. The file size threshold of one byte ensures that every
         * part is written to disk.
         */
        w.setMultipartConfigElement(new MultipartConfigElement(uploadDir.getAbsolutePath(), -1, -1, 1));
        ctx.addServletMappingDecoded("/", "parts");

        tomcat.getConnector().setMaxPostSize(MAX_POST_SIZE);

        tomcat.start();

        StringBuilder start = new StringBuilder();
        start.append("--").append(BOUNDARY).append(CRLF);
        // No file name so the part counts towards the post size
        start.append("Content-Disposition: form-data; name=\"p\"").append(CRLF);
        start.append(CRLF);
        for (int i = 0; i < UPLOADED_PART_SIZE; i++) {
            start.append('X');
        }
        start.append(CRLF);
        /*
         * The delimiter and the headers of the second part complete the first
         * part, so its temporary file is closed - and hence final - while the
         * parser waits for the body of the second part.
         */
        start.append("--").append(BOUNDARY).append(CRLF);
        start.append("Content-Disposition: form-data; name=\"q\"").append(CRLF);
        start.append(CRLF);

        byte[] bodyStart = start.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] bodyEnd = ("y" + CRLF + "--" + BOUNDARY + "--" + CRLF).getBytes(StandardCharsets.ISO_8859_1);

        String response;
        try (Socket socket = new Socket("localhost", getPort())) {
            socket.setSoTimeout(60000);

            StringBuilder head = new StringBuilder();
            head.append("POST / HTTP/1.1").append(CRLF);
            head.append("Host: localhost:").append(getPort()).append(CRLF);
            head.append("Connection: close").append(CRLF);
            head.append("Content-Type: multipart/form-data; boundary=").append(BOUNDARY).append(CRLF);
            head.append("Content-Length: ").append(bodyStart.length + bodyEnd.length).append(CRLF);
            head.append(CRLF);

            OutputStream os = socket.getOutputStream();
            os.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
            os.write(bodyStart);
            os.flush();

            inflateUploadedPart(uploadDir);

            os.write(bodyEnd);
            os.flush();

            response = readResponse(socket);
        }

        /*
         * Before the size tracking used long arithmetic the limit was not
         * applied to the over sized part at all and the request failed later,
         * when the part was converted to a parameter value, with a
         * NegativeArraySizeException that the container reported as a 500.
         */
        Assert.assertTrue(response, response.startsWith("HTTP/1.1 200"));
        Assert.assertTrue(response, response.contains("RESULT:IllegalStateException:published=0"));
    }


    /*
     * A part that exceeds maxPostSize without any overflow must still be
     * rejected and must not be exposed to the application.
     */
    @Test
    public void testMaxPostSizeExceededByNonFilePart() throws Exception {
        Assert.assertEquals("RESULT:IllegalStateException:published=0", doTestUpload(32, 128));
    }


    /*
     * Parts within maxPostSize must still be exposed to the application.
     */
    @Test
    public void testMaxPostSizeNotExceeded() throws Exception {
        Assert.assertEquals("RESULT:parts=2:published=2", doTestUpload(MAX_POST_SIZE, 8));
    }


    private String doTestUpload(int maxPostSize, int valueSize) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        File uploadDir = new File(getTemporaryDirectory(), "test-max-post-size-" + maxPostSize + "-" + valueSize);
        Assert.assertTrue(uploadDir.mkdirs());
        addDeleteOnTearDown(uploadDir);

        // No file system docBase required
        Context ctx = tomcat.addContext("", null);

        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        w.setMultipartConfigElement(new MultipartConfigElement(uploadDir.getAbsolutePath(), -1, -1, 1));
        ctx.addServletMappingDecoded("/", "parts");

        tomcat.getConnector().setMaxPostSize(maxPostSize);

        tomcat.start();

        StringBuilder body = new StringBuilder();
        for (String name : new String[] { "p", "q" }) {
            body.append("--").append(BOUNDARY).append(CRLF);
            body.append("Content-Disposition: form-data; name=\"").append(name).append('\"').append(CRLF);
            body.append(CRLF);
            for (int i = 0; i < valueSize; i++) {
                body.append('X');
            }
            body.append(CRLF);
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


    /*
     * Extends the temporary file that backs the part that has just been
     * uploaded so that FileUpload reports a size for it that does not fit in a
     * signed 32 bit int.
     */
    private static void inflateUploadedPart(File uploadDir) throws Exception {

        File tempFile = null;
        // The temporary file is complete once it has reached the uploaded size
        for (int i = 0; i < 1200 && tempFile == null; i++) {
            File[] files = uploadDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.length() >= UPLOADED_PART_SIZE) {
                        tempFile = file;
                        break;
                    }
                }
            }
            if (tempFile == null) {
                Thread.sleep(50);
            }
        }
        Assert.assertNotNull("No part was written to " + uploadDir.getAbsolutePath(), tempFile);

        try (RandomAccessFile raf = new RandomAccessFile(tempFile, "rw")) {
            // Extending a file does not allocate disk space for the extension
            raf.setLength(OVER_SIZED_PART);
        }
        Assert.assertEquals(OVER_SIZED_PART, tempFile.length());
    }


    private static String readResponse(Socket socket) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = socket.getInputStream();
        byte[] buffer = new byte[1024];
        int read = is.read(buffer);
        while (read > 0) {
            baos.write(buffer, 0, read);
            read = is.read(buffer);
        }
        return new String(baos.toByteArray(), StandardCharsets.ISO_8859_1);
    }


    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            String result;
            try {
                result = "parts=" + req.getParts().size();
            } catch (IllegalStateException ise) {
                result = "IllegalStateException";
            }

            /*
             * The parts the container published on the internal request. A part
             * that exceeds maxPostSize must never appear here, whether or not
             * the application goes on to call getParts().
             */
            Collection<Part> published = ((RequestFacade) req).request.parts;

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print("RESULT:" + result + ":published=" +
                    (published == null ? "null" : Integer.toString(published.size())));
        }
    }
}

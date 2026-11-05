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
package org.apache.catalina.valves;

import java.io.CharArrayWriter;
import java.util.Date;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Request;
import org.apache.catalina.valves.AbstractAccessLogValve.AccessLogElement;
import org.apache.tomcat.util.json.JSONParser;
import org.apache.tomcat.util.json.ParseException;

/**
 * The request URI and the query string are client controlled. Both used to be written to the access log without any
 * escaping which allowed a client to inject arbitrary content - including the quote and backslash characters that
 * delimit and escape values in the (JSON) access log - into the log output.
 */
public class TestAccessLogValveEscaping {

    private static final Date DATE = new Date();

    private static Request createRequest(String uri, String query) {
        Request request = new Request(null);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);
        coyoteRequest.method().setString("GET");
        coyoteRequest.protocol().setString("HTTP/1.1");
        coyoteRequest.requestURI().setString(uri);
        if (query != null) {
            coyoteRequest.queryString().setString(query);
        }
        return request;
    }


    private static String format(AccessLogElement element, Request request) {
        CharArrayWriter buf = new CharArrayWriter();
        element.addElement(buf, DATE, request, null, 0);
        return buf.toString();
    }


    private static String formatJson(String pattern, Request request) {
        JsonAccessLogValve valve = new JsonAccessLogValve();
        valve.setPattern(pattern);
        CharArrayWriter buf = new CharArrayWriter();
        for (AccessLogElement element : valve.logElements) {
            element.addElement(buf, DATE, request, null, 0);
        }
        return buf.toString();
    }


    private static Map<String,Object> parseJson(String logLine) throws ParseException {
        return new JSONParser(logLine).parseObject();
    }


    // ---------------------------------------------------------- %r - request

    @Test
    public void testRequestElementEscapesQuoteInUri() {
        String result = format(new AbstractAccessLogValve.RequestElement(), createRequest("/foo\"bar", null));
        Assert.assertEquals("GET /foo\\\"bar HTTP/1.1", result);
    }


    @Test
    public void testRequestElementEscapesBackslashInUri() {
        String result = format(new AbstractAccessLogValve.RequestElement(), createRequest("/foo\\bar", null));
        Assert.assertEquals("GET /foo\\\\bar HTTP/1.1", result);
    }


    @Test
    public void testRequestElementEscapesControlCharsInUri() {
        String result =
                format(new AbstractAccessLogValve.RequestElement(), createRequest("/foo\r\nGET /injected", null));
        Assert.assertEquals("GET /foo\\r\\nGET /injected HTTP/1.1", result);
    }


    @Test
    public void testRequestElementEscapesQueryString() {
        String result = format(new AbstractAccessLogValve.RequestElement(), createRequest("/foo", "a=\"b\"\\c"));
        Assert.assertEquals("GET /foo?a=\\\"b\\\"\\\\c HTTP/1.1", result);
    }


    @Test
    public void testRequestElementEmptyQueryString() {
        // Escaping must not turn a present but empty query string into "?-"
        String result = format(new AbstractAccessLogValve.RequestElement(), createRequest("/foo", ""));
        Assert.assertEquals("GET /foo? HTTP/1.1", result);
    }


    @Test
    public void testRequestElementNoQueryString() {
        String result = format(new AbstractAccessLogValve.RequestElement(), createRequest("/foo", null));
        Assert.assertEquals("GET /foo HTTP/1.1", result);
    }


    // ------------------------------------------------------------ %q - query

    @Test
    public void testQueryElementEscapesQueryString() {
        String result = format(new AbstractAccessLogValve.QueryElement(), createRequest("/foo", "a=\"b\"\\c"));
        Assert.assertEquals("?a=\\\"b\\\"\\\\c", result);
    }


    @Test
    public void testQueryElementEscapesControlChars() {
        String result = format(new AbstractAccessLogValve.QueryElement(), createRequest("/foo", "a=\r\nb\tc"));
        Assert.assertEquals("?a=\\r\\nb\\tc", result);
    }


    @Test
    public void testQueryElementEmptyQueryString() {
        // Escaping must not turn a present but empty query string into "?-"
        String result = format(new AbstractAccessLogValve.QueryElement(), createRequest("/foo", ""));
        Assert.assertEquals("?", result);
    }


    @Test
    public void testQueryElementNoQueryString() {
        String result = format(new AbstractAccessLogValve.QueryElement(), createRequest("/foo", null));
        Assert.assertEquals("-", result);
    }


    // ------------------------------------------------------- %U - requestURI

    @Test
    public void testRequestURIElementEscapesUri() {
        String result = format(new AbstractAccessLogValve.RequestURIElement(), createRequest("/foo\"\\\r\nbar", null));
        Assert.assertEquals("/foo\\\"\\\\\\r\\nbar", result);
    }


    // ------------------------------- JSON access log structure is not broken

    @Test
    public void testJsonNoInjectionViaRequestURI() throws ParseException {
        // The client controlled URI closes the JSON string and adds a field of its own
        String uri = "/foo\",\"injected\":\"yes";
        Map<String,Object> parsed = parseJson(formatJson("%U", createRequest(uri, null)));

        Assert.assertFalse("Client injected an additional field into the access log", parsed.containsKey("injected"));
        Assert.assertEquals(1, parsed.size());
        // The quotes are escaped so the whole URI remains a single value
        Assert.assertEquals("/foo\\\",\\\"injected\\\":\\\"yes", parsed.get("path"));
    }


    @Test
    public void testJsonNoInjectionViaQueryString() throws ParseException {
        String query = "a=1\",\"injected\":\"yes";
        Map<String,Object> parsed = parseJson(formatJson("%q", createRequest("/foo", query)));

        Assert.assertFalse("Client injected an additional field into the access log", parsed.containsKey("injected"));
        Assert.assertEquals(1, parsed.size());
        Assert.assertEquals("?a=1\\\",\\\"injected\\\":\\\"yes", parsed.get("query"));
    }


    @Test
    public void testJsonNoInjectionViaRequestLine() throws ParseException {
        String uri = "/foo\",\"injected\":\"yes";
        String query = "a=1\",\"alsoInjected\":\"yes";
        Map<String,Object> parsed = parseJson(formatJson("%r", createRequest(uri, query)));

        Assert.assertFalse("Client injected an additional field into the access log", parsed.containsKey("injected"));
        Assert.assertFalse("Client injected an additional field into the access log",
                parsed.containsKey("alsoInjected"));
        Assert.assertEquals(1, parsed.size());
        Assert.assertEquals("GET /foo\\\",\\\"injected\\\":\\\"yes?a=1\\\",\\\"alsoInjected\\\":\\\"yes HTTP/1.1",
                parsed.get("request"));
    }
}

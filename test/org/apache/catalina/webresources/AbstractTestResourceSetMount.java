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
package org.apache.catalina.webresources;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.WebResource;

public abstract class AbstractTestResourceSetMount
        extends AbstractTestResourceSet {

    @Override
    public final String getMount() {
        return "/mount";
    }

    @Test
    public final void testGetResourceAbove() {
        WebResource webResource = resourceRoot.getResource("/");
        Assert.assertFalse(webResource.exists());
    }

    @Test
    public final void testListAbove() {
        String[] results = resourceRoot.list("/");

        Assert.assertNotNull(results);
        Assert.assertEquals(1, results.length);
        Assert.assertEquals(getMount().substring(1), results[0]);
    }

    @Test
    public final void testListWebAppPathsAbove() {
        Set<String> results = resourceRoot.listWebAppPaths("/");

        Assert.assertNotNull(results);
        Assert.assertEquals(1, results.size());
        Assert.assertTrue(results.contains(getMount() + "/"));
    }

    @Test
    public void testMkdirAbove() {
        Assert.assertFalse(resourceRoot.mkdir("/"));
    }

    @Test
    public void testWriteAbove() {
        InputStream is = new ByteArrayInputStream("test".getBytes());
        Assert.assertFalse(resourceRoot.write("/", is, false));
    }

    /*
     * The following tests use a path that starts with the web application mount point but that is not within it. For a
     * resource set mounted at "/mount" that is a path such as "/mountd1". Such a path must not be treated as if it was
     * within the mount point since that exposes resources - and bypasses any security constraints defined for the
     * mount point - at a path where they should not be visible.
     */

    @Test
    public final void testGetResourceOutsideMount() {
        WebResource webResource = resourceRoot.getResource(getMount() + "d1/d1-f1.txt");
        Assert.assertFalse(webResource.exists());
        Assert.assertNull(webResource.getInputStream());
    }

    @Test
    public final void testListOutsideMount() {
        String[] results = resourceRoot.list(getMount() + "d1");

        Assert.assertNotNull(results);
        Assert.assertEquals(0, results.length);
    }

    @Test
    public final void testListWebAppPathsOutsideMount() {
        Assert.assertNull(resourceRoot.listWebAppPaths(getMount() + "d1"));
    }

    @Test
    public final void testMkdirOutsideMount() {
        boolean result = resourceRoot.mkdir(getMount() + getNewDirName());
        File file = new File(getBaseDir(), getNewDirName());
        boolean created = file.exists();
        if (created) {
            file.delete();
        }
        Assert.assertFalse(result);
        Assert.assertFalse(created);
    }

    @Test
    public final void testWriteOutsideMount() {
        InputStream is = new ByteArrayInputStream("test".getBytes());
        boolean result = resourceRoot.write(getMount() + getNewFileName(), is, false);
        File file = new File(getBaseDir(), getNewFileName());
        boolean created = file.exists();
        if (created) {
            file.delete();
        }
        Assert.assertFalse(result);
        Assert.assertFalse(created);
    }

    @Override
    public void testNoArgConstructor() {
        // NO-OP
    }
}

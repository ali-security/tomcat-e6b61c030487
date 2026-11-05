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
package org.apache.tomcat.util.net;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import org.apache.tomcat.util.compat.JreCompat;

/**
 * Tests the checks {@link NioEndpoint} applies to the directory where a Unix Domain Socket is created. The socket is
 * created with default permissions and the configured permissions are applied afterwards so, to avoid a TOCTOU issue,
 * the parent directory must already restrict access to the socket when it is created.
 */
public class TestNioEndpointUnixDomainSocket {

    private static final String SOCKET_NAME = "tomcat.sock";

    private Path baseDir;
    private NioEndpoint endpoint;


    @Before
    public void setUp() throws IOException {
        Assume.assumeTrue("Unix Domain Sockets require Java 16+", JreCompat.isJre16Available());
        baseDir = Files.createTempDirectory("uds-tomcat-test-");
        Assume.assumeTrue("Test requires a POSIX file system",
                baseDir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        endpoint = new NioEndpoint();
    }


    @After
    public void tearDown() throws Exception {
        if (endpoint != null) {
            endpoint.destroy();
        }
        if (baseDir != null) {
            delete(baseDir);
        }
    }


    @Test
    public void testParentWritableByOthersRejected() throws Exception {
        // A directory where any user can create, delete or replace the socket during the TOCTOU window
        doTestParentLaxPermissionsRejected("rwxrwxrwx", "rw-------");
    }


    @Test
    public void testParentAccessibleByOthersRejected() throws Exception {
        // A directory where any user can reach the socket before the restrictive permissions are applied
        doTestParentLaxPermissionsRejected("rwxr-xr-x", "rw-------");
    }


    @Test
    public void testParentWritableByGroupRejected() throws Exception {
        // Group members may connect but must not be able to replace the socket
        doTestParentLaxPermissionsRejected("rwxrwx---", "rw-rw----");
    }


    private void doTestParentLaxPermissionsRejected(String parentPermissions, String socketPermissions)
            throws Exception {
        Files.setPosixFilePermissions(baseDir, PosixFilePermissions.fromString(parentPermissions));
        Path udsPath = baseDir.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(udsPath.toString());
        endpoint.setUnixDomainSocketPathPermissions(socketPermissions);
        endpoint.setUnixDomainSocketParentOwner(getOwner(baseDir));

        try {
            endpoint.init();
            Assert.fail("Unix Domain Socket created in directory with permissions [" + parentPermissions + "]");
        } catch (IllegalStateException expected) {
            // Expected
        }
        Assert.assertFalse(Files.exists(udsPath, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testMissingParentCreatedOwnerOnly() throws Exception {
        doTestMissingParentCreated("rw-------", null, "rwx------");
    }


    @Test
    public void testMissingParentCreatedGroup() throws Exception {
        doTestMissingParentCreated("rw-rw----", null, "rwxr-x---");
    }


    @Test
    public void testMissingParentCreatedAll() throws Exception {
        doTestMissingParentCreated("rw-rw-rw-", null, "rwxr-xr-x");
    }


    @Test
    public void testMissingParentCreatedExplicit() throws Exception {
        doTestMissingParentCreated("rw-rw-rw-", "rwx------", "rwx------");
    }


    private void doTestMissingParentCreated(String socketPermissions, String parentPermissions,
            String expectedParentPermissions) throws Exception {
        Path parent = baseDir.resolve("uds");
        Path udsPath = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(udsPath.toString());
        endpoint.setUnixDomainSocketPathPermissions(socketPermissions);
        endpoint.setUnixDomainSocketParentPermissions(parentPermissions);
        endpoint.setUnixDomainSocketParentOwner(getOwner(baseDir));

        endpoint.init();

        Assert.assertEquals(PosixFilePermissions.fromString(expectedParentPermissions),
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
        Assert.assertEquals(PosixFilePermissions.fromString(socketPermissions),
                Files.getPosixFilePermissions(udsPath, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testExistingParentAccepted() throws Exception {
        Files.setPosixFilePermissions(baseDir, PosixFilePermissions.fromString("rwx------"));
        Path udsPath = baseDir.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(udsPath.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentOwner(getOwner(baseDir));

        endpoint.init();

        Assert.assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(udsPath, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testParentChecksSkipped() throws Exception {
        Files.setPosixFilePermissions(baseDir, PosixFilePermissions.fromString("rwxrwxrwx"));
        Path udsPath = baseDir.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(udsPath.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        // Explicitly disable the checks on the parent directory
        endpoint.setUnixDomainSocketParentPermissions("");

        endpoint.init();

        Assert.assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(udsPath, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testParentSymlinkRejected() throws Exception {
        Path target = Files.createDirectory(baseDir.resolve("target"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path link = Files.createSymbolicLink(baseDir.resolve("link"), target);
        Path udsPath = link.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(udsPath.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentOwner(getOwner(baseDir));

        try {
            endpoint.init();
            Assert.fail("Unix Domain Socket created via a symbolic link to the parent directory");
        } catch (IllegalStateException | IOException expected) {
            // Expected
        }
        Assert.assertFalse(Files.exists(target.resolve(SOCKET_NAME), LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testParentOwnedByOtherUserRejected() throws Exception {
        // The root directory is used as an existing directory that is owned by a different user
        Path root = baseDir.getRoot();
        String rootOwner = getOwner(root);
        Assume.assumeFalse("Test requires the root directory to be owned by a different user",
                rootOwner.equals(getOwner(baseDir)) || rootOwner.equals(System.getProperty("user.name")));

        Path udsPath = root.resolve("uds-tomcat-test-" + System.nanoTime() + ".sock");
        endpoint.setUnixDomainSocketPath(udsPath.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        // Use the current permissions so only the owner check can reject the directory
        endpoint.setUnixDomainSocketParentPermissions(
                PosixFilePermissions.toString(Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS)));

        try {
            endpoint.init();
            Assert.fail("Unix Domain Socket created in directory owned by [" + rootOwner + "]");
        } catch (IllegalStateException expected) {
            // Expected
        }
        Assert.assertFalse(Files.exists(udsPath, LinkOption.NOFOLLOW_LINKS));
    }


    private static String getOwner(Path path) throws IOException {
        return Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName();
    }


    private static void delete(Path path) throws IOException {
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            try (DirectoryStream<Path> children = Files.newDirectoryStream(path)) {
                for (Path child : children) {
                    delete(child);
                }
            }
        }
        Files.deleteIfExists(path);
    }
}

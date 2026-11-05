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
package org.apache.tomcat.util.compat;

/**
 * Reports how the Java 11 ({@link JreCompat}) and Java 12 to 20 ({@link Jre12Compat})
 * implementations of {@code isCanonCachesDisabled()} interpret the command line this JVM was
 * started with. Driven by {@code TestJreCompat} which starts this class in a forked JVM.
 * <p>
 * Named {@code Tester*} so that the Ant build does not collect it as a test case.
 */
public class TesterJreCompatCanonCaches {

    public static void main(String[] args) {
        /*
         * The answer is cached in a static field shared by every implementation so it has to be
         * reset between the two implementations under test.
         */
        JreCompat.canonCachesDisabled = null;
        System.out.println("BASE_DISABLED=" + new JreCompat().isCanonCachesDisabled());

        JreCompat.canonCachesDisabled = null;
        System.out.println("JRE12_DISABLED=" + new Jre12Compat().isCanonCachesDisabled());

        JreCompat.canonCachesDisabled = null;
        System.out.println("INSTANCE=" + JreCompat.getInstance().getClass().getName());
        System.out.println("DONE");
    }
}

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
package org.apache.catalina.tribes.util;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import org.junit.Assert;
import org.junit.Test;

public class TestStringManager {

    private static final String PACKAGE_NAME = "org.apache.catalina.tribes.util";


    @Test
    public void testGetManagerWithLocales() {
        List<Locale> locales = Arrays.asList(Locale.FRENCH, Locale.GERMAN);
        StringManager sm = StringManager.getManager(PACKAGE_NAME, Collections.enumeration(locales));
        Assert.assertEquals(Locale.FRENCH, sm.getLocale());

        locales = Arrays.asList(Locale.GERMAN, Locale.FRENCH);
        sm = StringManager.getManager(PACKAGE_NAME, Collections.enumeration(locales));
        Assert.assertEquals(Locale.GERMAN, sm.getLocale());
    }


    @Test
    public void testGetManagerWithLocalesSkipsMissingBundles() {
        // Locales without an exact match bundle must be skipped
        List<Locale> locales = Arrays.asList(Locale.forLanguageTag("xxxxx"), Locale.FRENCH);
        StringManager sm = StringManager.getManager(PACKAGE_NAME, Collections.enumeration(locales));
        Assert.assertEquals(Locale.FRENCH, sm.getLocale());

        // No exact match at all - the default is returned
        locales = Collections.singletonList(Locale.forLanguageTag("xxxxx"));
        sm = StringManager.getManager(PACKAGE_NAME, Collections.enumeration(locales));
        Assert.assertEquals(StringManager.getManager(PACKAGE_NAME).getLocale(), sm.getLocale());
    }


    @Test
    public void testGetManagerWithLocalesResourceBundleCacheUsage() throws Exception {
        int initial = resourceBundleCacheSize();

        for (int i = 0; i < 5; i++) {
            List<Locale> locales = new ArrayList<>();
            for (int j = 0; j < 1000; j++) {
                locales.add(fakeLocale(i * 1000 + j));
            }
            StringManager.getManager(PACKAGE_NAME, Collections.enumeration(locales));
        }

        int delta = resourceBundleCacheSize() - initial;
        Assert.assertTrue("ResourceBundle cache grew by " + delta + " entries for 5000 unknown locales",
                delta < 100);
    }


    private static Locale fakeLocale(int i) {
        StringBuilder language = new StringBuilder("xxxxx");
        int v = i;
        for (int k = 4; k >= 0; k--) {
            language.setCharAt(k, (char) ('a' + v % 26));
            v /= 26;
        }
        return Locale.forLanguageTag(language.toString());
    }


    @SuppressWarnings("unchecked")
    private static int resourceBundleCacheSize() throws Exception {
        Field field = ResourceBundle.class.getDeclaredField("cacheList");
        field.setAccessible(true);
        Map<Object,Object> cache = (Map<Object,Object>) field.get(null);
        return cache.size();
    }
}

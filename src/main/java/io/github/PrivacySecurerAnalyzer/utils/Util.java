package io.github.PrivacySecurerAnalyzer.utils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Logger;

import io.github.PrivacySecurerAnalyzer.Config;

public class Util {
    public static final Logger LOGGER = Logger.getLogger(Config.PROJECT_NAME);
    public static final String UNKNOWN = "<unknown>";

    public static String getTimeString() {
        long timeMillis = System.currentTimeMillis();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd-hhmmss");
        Date date = new Date(timeMillis);
        return sdf.format(date);
    }

    public static void logException(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        Util.LOGGER.warning(sw.toString());
    }

    public static float safeDivide(int obfuscated, int total) {
        if (total <= 0) return 1;
        return (float) obfuscated / total;
    }

}
package io.github.PrivacySecurerAnalyzer.utils;

import java.util.ListIterator;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.ParseException;

public class IgnoreUnknownTokenParser extends BasicParser {
    @Override
    protected void processOption(final String arg, final ListIterator iter) throws ParseException {
        boolean hasOption = getOptions().hasOption(arg);

        if (hasOption) {
            super.processOption(arg, iter);
        }
    }
}

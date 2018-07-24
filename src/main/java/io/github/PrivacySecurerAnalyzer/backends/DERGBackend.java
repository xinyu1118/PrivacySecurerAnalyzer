package io.github.PrivacySecurerAnalyzer.backends;

import java.util.HashMap;

import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.StringUtils;

import io.github.PrivacySecurerAnalyzer.backends.graph_export.GraphExporter;
import io.github.PrivacySecurerAnalyzer.core.Graph;
import io.github.PrivacySecurerAnalyzer.utils.Util;

public abstract class DERGBackend {
	public static HashMap<String, DERGBackend> availableBackends = new HashMap<>();
    public static String defaultBackend = "";
    public static void registerBackends() {
        defaultBackend = GraphExporter.NAME;
        availableBackends.put(GraphExporter.NAME, new GraphExporter());
    }
    public static String getAvailableBackends() {
        return StringUtils.join(availableBackends.keySet(), "/");
    }
    
    public void parseArgs(String[] args) throws ParseException {}
    
    public abstract void run(Graph g);
    
    public static DERGBackend get(String type) {
    	if (type == null || type.length() == 0) {
    		Util.LOGGER.warning(String.format("no backend specified, using %s by default", defaultBackend));
            type = defaultBackend;
        }
        if (availableBackends.containsKey(type)) {
            return availableBackends.get(type);
        }
        return null;
    }

}

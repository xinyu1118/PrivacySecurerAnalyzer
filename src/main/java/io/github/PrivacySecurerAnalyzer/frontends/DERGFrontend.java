package io.github.PrivacySecurerAnalyzer.frontends;

import java.util.HashMap;

import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.StringUtils;

import io.github.PrivacySecurerAnalyzer.core.Graph;
import io.github.PrivacySecurerAnalyzer.frontends.soot.ApkAnalyzer;
import io.github.PrivacySecurerAnalyzer.utils.Util;

public abstract class DERGFrontend {
	//private static final String JSONBuilder = null;
	public static HashMap<String, DERGFrontend> availableFrontends = new HashMap<>();
	public static String defaultFrontend = "";
	 
	 public static void registerFrontends() {
		 defaultFrontend = ApkAnalyzer.NAME;  
		 availableFrontends.put(ApkAnalyzer.NAME, new ApkAnalyzer());
		 //availableFrontends.put(JSONBuilder.NAME, new JSONBuilder());
	 }
	 
	 public static String getAvailableFrontends() {
		 return StringUtils.join(availableFrontends.keySet(), "/");
	 }
	 
	 public abstract Graph build();
	 
	 public void parseArgs(String[] args) throws ParseException {}
	 
	 public static DERGFrontend getBuilder(String type) {
		 if (type == null || type.length() == 0) {
			 Util.LOGGER.warning(String.format("no frontend specified, using %s by default", defaultFrontend));
			 type = defaultFrontend;
		 }
		 if (availableFrontends.containsKey(type)) {
			 return availableFrontends.get(type);
		 }
		 return null;
	 }
}

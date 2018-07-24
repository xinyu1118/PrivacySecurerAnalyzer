package io.github.PrivacySecurerAnalyzer;

public class Main {
	public static void main(String args[]) {
		Config.init();
        if (!Config.parseArgs(args)) {
            return;
        } 

        Config.dergFrontend.build();
        //Config.dergBackend.run(g);
	}
}

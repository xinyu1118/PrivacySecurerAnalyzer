package io.github.PrivacySecurerAnalyzer.frontends.soot;

import java.util.ArrayList;
import java.util.List;

public class PackageNode {
    private String packageName;
    private String segName;

    public PackageNode(String packageName, String segName) {
        assert packageName.endsWith(segName);
        this.packageName = packageName;
        this.segName = segName;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PackageNode))
            return false;
        PackageNode other = (PackageNode) obj;
        return this.packageName.equals(other.packageName)
                && this.segName.equals(other.segName);
    }

    public String getSegName() {
        return this.segName;
    }

    public int hashCode() {
        return packageName.hashCode();
    }

    public static List<PackageNode> parsePackageSegs(String packageName) {
        List<PackageNode> result = new ArrayList<>();
        String[] segs = packageName.split("\\.");
        String packagePath = "";
        for (String seg : segs) {
            packagePath += "." + seg;
            PackageNode packageSeg = new PackageNode(packagePath, seg);
            result.add(packageSeg);
        }
        return result;
    }
}
package io.github.PrivacySecurerAnalyzer.core;

import org.apache.commons.lang.StringUtils;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.internal.AbstractDefinitionStmt;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.LocalUses;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class PSPipeline extends PSFunction {

    protected List<Object> nextPipelines;

    public PSPipeline(InvokeExpr invokeExpr, Unit hostUnit, SootMethod hostMethod, Body hostBody, LocalDefs localDefs, LocalUses localUses) {
        super(invokeExpr, hostUnit, hostMethod, hostBody, localDefs, localUses);
        this.nextPipelines = new ArrayList<>();
        this.findNextPipelines();
    }

    private void findNextPipelines() {
        List<UnitValueBoxPair> uses = this.localUses.getUsesOf(this.hostUnit);

        Value definedValue = null;
        if (this.hostUnit instanceof AbstractDefinitionStmt) {
            definedValue = ((AbstractDefinitionStmt) this.hostUnit).getLeftOp();
        }

        for (UnitValueBoxPair unitValueBoxPair : uses) {
            Unit useUnit = unitValueBoxPair.getUnit();

            // Find next InvokeExpr
            InvokeExpr invokeExpr = null;
            if (useUnit instanceof AbstractDefinitionStmt) {
                Value rightOp = ((AbstractDefinitionStmt) useUnit).getRightOp();
                if (rightOp instanceof InvokeExpr) {
                    invokeExpr = (InvokeExpr) rightOp;
                }
            }
            else if (useUnit instanceof InvokeStmt) {
                invokeExpr = ((InvokeStmt) useUnit).getInvokeExpr();
            }

            if (invokeExpr != null && invokeExpr.getMethod().getDeclaringClass().getShortName().contains("Stream")) {
                this.nextPipelines.add(new PSPipeline(invokeExpr, useUnit, hostMethod, hostBody, localDefs, localUses));
                continue;
            }
            this.nextPipelines.add(definedValue);

        }
    }

    public String toString(int indent) {
        String thisIndent = StringUtils.repeat(" ", indent);
        String result = thisIndent + super.toString();
        for (Object psPipeline : this.nextPipelines) {
            result += "\n";
            if (psPipeline == null) result += StringUtils.repeat(" ", indent + 2) + "<unknown>";
            else if (psPipeline instanceof PSPipeline) result += ((PSPipeline)psPipeline).toString(indent + 2);
            else result += StringUtils.repeat(" ", indent + 2) + psPipeline;
        }
        return result;
    }

    public String toString() {
        return String.format("PrivacyStreams DFG in method %s\n%s", this.hostMethod, this.toString(2));
    }
}

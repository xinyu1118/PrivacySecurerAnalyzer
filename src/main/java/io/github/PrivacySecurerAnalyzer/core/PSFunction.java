package io.github.PrivacySecurerAnalyzer.core;

import org.apache.commons.lang.StringUtils;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.AbstractDefinitionStmt;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.LocalUses;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.util.ArrayList;
import java.util.List;

public class PSFunction {
    protected Object base;
    protected List<Object> parameters;

    protected InvokeExpr invokeExpr;
    protected Unit hostUnit;
    protected SootMethod hostMethod;
    protected Body hostBody;
    protected LocalDefs localDefs;
    protected LocalUses localUses;

    public PSFunction(InvokeExpr invokeExpr, Unit hostUnit, SootMethod hostMethod, Body hostBody, LocalDefs localDefs, LocalUses localUses) {
        this.invokeExpr = invokeExpr;
        this.hostUnit = hostUnit;
        this.hostMethod = hostMethod;
        this.hostBody = hostBody;
        this.localDefs = localDefs;
        this.localUses = localUses;
        this.parameters = new ArrayList<>();
        this.findParameters();
    }

    private void findParameters() {
        for (Value parameter : this.invokeExpr.getArgs()) {
            Object parameterDef = this.getParameterDef(parameter, this.hostUnit);
            if (parameterDef == null)
                this.parameters.add(parameter);
            else
                this.parameters.add(parameterDef);
        }
        if (this.invokeExpr instanceof InstanceInvokeExpr) {
            String baseType = this.invokeExpr.getMethod().getDeclaringClass().getShortName();
            switch (baseType) {
                case "UQI":
                    this.base = "UQI";
                    break;
                case "PStream":
                    this.base = "";
                    break;
                default:
                    this.base = this.getParameterDef(((InstanceInvokeExpr) this.invokeExpr).getBase(), this.hostUnit);
                    break;
            }
        }
    }

    private Object getParameterDef(Value parameter, Unit currentUnit) {
        if (parameter instanceof Constant) {
            return parameter;
        }
        if (parameter instanceof Local) {
            List<Unit> paraDefs = this.localDefs.getDefsOfAt((Local) parameter, currentUnit);
            if (paraDefs.size() == 1 && paraDefs.get(0) instanceof AbstractDefinitionStmt) {
                AbstractDefinitionStmt stmt = (AbstractDefinitionStmt) paraDefs.get(0);
                if (stmt.getRightOp() instanceof InvokeExpr) {
                    return new PSFunction((InvokeExpr) stmt.getRightOp(), stmt, this.hostMethod, this.hostBody, this.localDefs, this.localUses);
                }
                if (stmt.getRightOp() instanceof NewArrayExpr) {
                    List<Object> parameterArray = new ArrayList<>();
                    List<UnitValueBoxPair> uses = this.localUses.getUsesOf(stmt);
                    for (UnitValueBoxPair unitValueBoxPair : uses) {
                        Unit useUnit = unitValueBoxPair.getUnit();
                        // Find all array elements
                        if (useUnit instanceof AbstractDefinitionStmt) {
                            Value leftOp = ((AbstractDefinitionStmt) useUnit).getLeftOp();
                            if (leftOp instanceof ArrayRef) {
                                Value rightOp = ((AbstractDefinitionStmt) useUnit).getRightOp();
                                Object arrayElement = this.getParameterDef(rightOp, useUnit);
                                parameterArray.add(arrayElement);
                            }
                        }
                    }
                    return parameterArray;
                }
                if (stmt.getRightOp() instanceof Local) {
                    return this.getParameterDef(stmt.getRightOp(), stmt);
                }
            }
        }
        return null;
    }

    public String toString() {
        if (this.invokeExpr instanceof InstanceInvokeExpr) {
            return String.format("%s.%s(%s)",
                    this.base,
                    this.invokeExpr.getMethod().getName(), StringUtils.join(this.parameters, ", "));
        }
        else {
            return String.format("%s.%s(%s)",
                    this.invokeExpr.getMethod().getDeclaringClass().getShortName(),
                    this.invokeExpr.getMethod().getName(), StringUtils.join(this.parameters, ", "));
        }
    }
}

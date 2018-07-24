package io.github.PrivacySecurerAnalyzer.frontends.soot;

import io.github.PrivacySecurerAnalyzer.Config;
import io.github.PrivacySecurerAnalyzer.Const;
import io.github.PrivacySecurerAnalyzer.core.Edge;
import io.github.PrivacySecurerAnalyzer.core.Graph;
import io.github.PrivacySecurerAnalyzer.core.Node;
import io.github.PrivacySecurerAnalyzer.core.PSPipeline;
import io.github.PrivacySecurerAnalyzer.frontends.DERGFrontend;
import io.github.PrivacySecurerAnalyzer.utils.IgnoreUnknownTokenParser;
import io.github.PrivacySecurerAnalyzer.utils.Util;
import org.apache.commons.cli.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.internal.runners.statements.InvokeMethod;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.AbstractDefinitionStmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JCastExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JNewArrayExpr;
import soot.jimple.internal.JimpleLocal;
import soot.options.Options;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.*;

import java.io.File;
import java.io.FileFilter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

public class ApkAnalyzer extends DERGFrontend {
	public static final String NAME = "apk";
	public static final String DESCRIPTION = "Build PrivacySecurer Descriptions from .apk file.";

	private ArrayList<SootClass> applicationClasses;
	
	private ArrayList<ArrayList<String>> argsNameValue = new ArrayList<ArrayList<String>>();

	// File path of android.jar which is forced to use by soot
	private String forceAndroidJarPath = "";
	// Libraries' directory, to be added to soot classpath
	private String librariesDir = "";

	public void parseArgs(String[] args) throws ParseException {
		org.apache.commons.cli.Options options = new org.apache.commons.cli.Options();
		Option library = Option.builder("l").argName("directory").longOpt("library").hasArg()
				.desc("path to library dir").build();
		Option sdk = Option.builder("sdk").argName("android.jar").longOpt("android-sdk").hasArg()
				.desc("path to android.jar").build();
		Option help_opt = Option.builder("h").desc("print this help message").longOpt("help").build();

		options.addOption(library);
		options.addOption(sdk);
		options.addOption(help_opt);

		CommandLineParser parser = new IgnoreUnknownTokenParser();

		try {
			CommandLine cmd = parser.parse(options, args);
			if (cmd.hasOption('l')) {
				librariesDir = cmd.getOptionValue('l');
				File lib = new File(librariesDir);
				if (!lib.exists()) {
					throw new ParseException("Library does not exist.");
				}
				if (lib.isFile() && !lib.getName().endsWith(".jar")) {
					throw new ParseException("Library format error, should be directory or jar.");
				}
			}
			if (cmd.hasOption("sdk")) {
				forceAndroidJarPath = cmd.getOptionValue("sdk");
				File sdkFile = new File(forceAndroidJarPath);
				if (!sdkFile.exists()) {
					throw new ParseException("Android jar does not exist.");
				}
			}
			if (cmd.hasOption("h")) {
				throw new ParseException("print help message.");
			}
		} catch (ParseException e) {
			System.out.println(e.getMessage());
			HelpFormatter formatter = new HelpFormatter();
			formatter.setOptionComparator(new Comparator<Option>() {
				@Override
				public int compare(Option o1, Option o2) {
					return o1.getOpt().length() - o2.getOpt().length();
				}
			});
			formatter.printHelp(ApkAnalyzer.NAME, options, true);
			throw new ParseException("Parsing arguments failed in " + ApkAnalyzer.NAME);
		}
	}

	private boolean init() {
		Util.LOGGER.info("Start Initializing " + ApkAnalyzer.NAME);
		Options.v().set_debug(false);
		Options.v().set_prepend_classpath(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_dir(Config.outputDir);

		List<String> process_dirs = new ArrayList<>();
		process_dirs.add(Config.inputDirOrFile);
		Options.v().set_process_dir(process_dirs);

		if (Config.inputDirOrFile.endsWith(".apk")) {
			Options.v().set_src_prec(Options.src_prec_apk);
			Options.v().set_output_format(Options.output_format_dex);
		} else if (Config.inputDirOrFile.endsWith(".jar")) {
			Options.v().set_src_prec(Options.src_prec_class);
			Options.v().set_output_jar(true);
		} else {
			Options.v().set_src_prec(Options.src_prec_java);
			Options.v().set_output_format(Options.output_format_jimple);
		}

		String classpath = "";
		if (this.librariesDir != null && this.librariesDir.length() != 0) {
			File lib = new File(this.librariesDir);
			if (lib.isFile() && lib.getName().endsWith(".jar"))
				classpath = lib.getAbsolutePath();
			else if (lib.isDirectory()) {
				FileFilter fileFilter = new FileFilter() {
					@Override
					public boolean accept(File pathname) {
						return pathname.getName().endsWith(".jar");
					}
				};
				for (File file : lib.listFiles(fileFilter)) {
					classpath += file.getAbsolutePath() + ";";
				}
			}
			Options.v().set_soot_classpath(classpath);
		}

		Options.v().set_force_android_jar(this.forceAndroidJarPath);

		Scene.v().loadNecessaryClasses();

		applicationClasses = new ArrayList<>();
		for (SootClass cls : Scene.v().getApplicationClasses()) {
			applicationClasses.add(cls);
		}
		Collections.sort(applicationClasses, new Comparator<SootClass>() {
			@Override
			public int compare(SootClass o1, SootClass o2) {
				return String.CASE_INSENSITIVE_ORDER.compare(o1.getName(), o2.getName());
			}
		});
		Util.LOGGER.info("Finish Initializing " + ApkAnalyzer.NAME);
		return true;
	}

	public void addAPICallRelations(Graph g, SootMethod method) {
		// consider the scope inside a method
		if (method.getSource() == null)
			return;
		Node v_method = getMethodNode(g, method);

		Node v_root = g.genDefaultRoot();
		g.createEdge(v_root, v_method, Edge.TYPE_CONTAINS);

		try {
			Body body = method.retrieveActiveBody();

			// add reference relation
			for (ValueBox valueBox : body.getUseAndDefBoxes()) {
				Value value = valueBox.getValue();
				if (value instanceof InvokeExpr) {
					SootMethod invokedMethod = ((InvokeExpr) value).getMethod();
					SootClass invokedClass = invokedMethod.getDeclaringClass();
					if (invokedClass == null || invokedClass.isApplicationClass())
						continue;

					List<Value> arguments = ((InvokeExpr) value).getArgs();
					Node v_api = getAPINode(g, invokedMethod, arguments);

					g.createEdge(v_method, v_api, Edge.TYPE_REFER);

					System.out.println(v_api.name);
				}
			}
		} catch (Exception e) {
			Util.logException(e);
		}
	}

	public static Node getAPINode(Graph g, SootMethod apiMethod, List<Value> parameters) {
		String methodStr = apiMethod.getSignature();
		for (Value parameter : parameters) {
			methodStr += "-----" + parameter.toString();
		}

		Node result = g.getNodeOrCreate(apiMethod, methodStr, Node.TYPE_API);
		result.sig = apiMethod.getSignature();
		return result;
	}

	public static Node getPackageNode(Graph g, PackageNode pkgNode) {
		return g.getNodeOrCreate(pkgNode, pkgNode.getSegName(), Node.TYPE_PACKAGE);
	}

	public static Node getClassNode(Graph g, SootClass cls) {
		Node result = g.getNodeOrCreate(cls, cls.getShortName(), Node.TYPE_CLASS);
		result.sig = cls.getName();
		return result;
	}

	public static Node getMethodNode(Graph g, SootMethod method) {
		Node result = g.getNodeOrCreate(method, method.getName(), Node.TYPE_METHOD);
		result.sig = method.getSignature();
		return result;
	}

	public static Node getFieldNode(Graph g, SootField field) {
		Node result = g.getNodeOrCreate(field, field.getName(), Node.TYPE_FIELD);
		result.sig = field.getSignature();
		return result;
	}

	public static Node getTypeNode(Graph g, Type type) {
		if (type instanceof RefType) {
			RefType refType = (RefType) type;
			return getClassNode(g, refType.getSootClass());
		}
		return g.getNodeOrCreate(type, type.toString(), Node.TYPE_TYPE);
	}

	public static Node getConstNode(Graph g, Constant con) {
		return g.getNodeOrCreate(con, con.toString(), Node.TYPE_CONST);
	}

	SootMethod getStreamAPI;

	private Map<String, String> psMethod2Sig = new HashMap<>();
	private Set<String> androidApiUsed = new HashSet<>();
	
	private String eventType = null;
	private String fieldName = null;
	private String comparator = null;
	private String threshold = null; 
	private String latitude = null;
	private String longitude = null;
	private String radius = null;
	private String placeName = null;
	private String lists = null;
	private String varargs = null;
	private String tempLists = "";
//	private String tempVarargs = "";
	private ArrayList<String> tempVarargs = new ArrayList<>();
	private String caller = null;
	private String path = null;
	private String duration = null;
	private String interval = null;
	private String locationPrecision = null;
	private String recurrence = null;
	private ArrayList<String> optimizationConstraints = new ArrayList<>();

	private Set<SootMethod> findPendingMethods() {
		Set<SootMethod> pendingMethods = new HashSet<>();

		for (SootClass cls : this.applicationClasses) {
			// generate signature mappings of all methods in io.github.privacysecurer packages
			if (cls.getPackageName().startsWith(Const.psPackage)) {
				List<SootMethod> psMethods = new ArrayList<>();
				for (SootMethod method : cls.getMethods()) {
					psMethods.add(method);
				}
				for (SootMethod method : psMethods) {
					if (method.getSource() == null)
						continue;
					String methodSig = this.getPSMethodSig(method);
					psMethod2Sig.put(method.getSignature(), methodSig);
				}
			}

			List<SootMethod> methods = new ArrayList<>();
			for (SootMethod method : cls.getMethods()) {
				methods.add(method);
			}
			for (SootMethod method : methods) {
				if (method.getSource() == null)
					continue;
				try {
					Body body = method.retrieveActiveBody();
					Iterator<Unit> unitsIterator = body.getUnits().snapshotIterator();
					while (unitsIterator.hasNext()) {
						Stmt stmt = (Stmt) unitsIterator.next();
						if (stmt.containsInvokeExpr()) {
							SootMethod sootMethod = stmt.getInvokeExpr().getMethod();
							// if SootMethod contains addEventListener() method ,find event parameter settings
							if (sootMethod == getStreamAPI) {
								//pendingMethods.add(sootMethod);
								pendingMethods.add(method);
							}
							
							if (!sootMethod.getDeclaringClass().isApplicationClass()) {
								androidApiUsed.add(sootMethod.getSignature());
							}
						}
					}
				} catch (Exception e) {
					Util.logException(e);
				}
			}
		}
		return pendingMethods;
	}

	private String getPSMethodSig(SootMethod method) {
		try {
			Body body = method.retrieveActiveBody();

			Set<String> methodSigs = new HashSet<>();

			for (ValueBox valueBox : body.getUseAndDefBoxes()) {
				Value value = valueBox.getValue();
				if (value instanceof FieldRef) {
					if (((FieldRef) value).getField().getDeclaringClass().isApplicationClass())
						continue;
					methodSigs.add(((FieldRef) value).getField().getSignature());
				} else if (value instanceof InvokeExpr) {
					if (((InvokeExpr) value).getMethod().getDeclaringClass().isApplicationClass())
						continue;
					methodSigs.add(((InvokeExpr) value).getMethod().getSignature());
				} else if (value instanceof Constant) {
					methodSigs.add(value.toString());
				}
			}

			List<String> sortedMethodSigs = new ArrayList<>(methodSigs);
			Collections.sort(sortedMethodSigs);
			return DigestUtils.sha256Hex(sortedMethodSigs.toString());
		} catch (Exception e) {
			Util.logException(e);
		}
		return "<UNKNOWN>";
	}
	
	private void findAPIMethod(SootMethod method) {
		StaticFieldRef staticFieldRef = null;
		ValueBox staticValueBox = null;
		
		Body body = method.retrieveActiveBody();
		Iterator<Unit> unitsIterator = body.getUnits().snapshotIterator();
		
		while (unitsIterator.hasNext()) {
			ArrayList<String> argNameValue = new ArrayList<>();
			Stmt stmt = (Stmt) unitsIterator.next();
			
			// Find out setList(blacklist) parameters assigned at runtime,
			// then obtain and store lists by searching values in 'add' method. 
			if (stmt instanceof JInvokeStmt) {
				JInvokeStmt jis = (JInvokeStmt)stmt;
				InvokeExpr ie = jis.getInvokeExpr();
				if (ie.getMethod().getName().equals("add")) {
					for(ValueBox value : ie.getUseBoxes()) {
						if (value.getValue() instanceof StringConstant) {
							tempLists = tempLists.concat(value.getValue().toString());
						}
					}
				}
			}
			
			// Find out event assignment statements
			if (stmt instanceof JAssignStmt) {
				JAssignStmt js = (JAssignStmt)stmt;
				Value js_rOp = js.getRightOp();
				
				// Find out functions used in setField(fieldName, fieldCalculationFunction)
				if (js_rOp.getType().toString().equals("io.github.privacystreamsevents.core.Function")) {
					SootMethod builtInFunction = ((StaticInvokeExpr) js_rOp).getMethod();
					String builtInFunctionName = builtInFunction.getName();
					System.out.printf("Built-in function is %s, ", builtInFunctionName);
					// Print the input and output of built-in function used in PrivacyStreamsEvents API
					switch(builtInFunctionName) {
						case "calcAvgLoudness":
							System.out.println("with AUDIO_DATA input and avgLoudness output.");
							break;
						case "calcMaxLoudness":
							System.out.println("with AUDIO_DATA input and maxLoudness output.");
							break;
						case "getLatLon":
							System.out.println("outputting location.");
							break;
						case "calcSpeed":
							System.out.println("outputting speed.");
							break;
						case "distanceTo":
							System.out.println("with LAN_LON input and distance output.");
							break;
						case "getDirection":
							System.out.println("outputting direction.");
							break;
						case "getPostcode":
							System.out.println("with LAN_LON input and postcode output.");
							break;
						case "getCity":
							System.out.println("with LAN_LON input and city output.");
							break;
						case "callerIdentification":
							System.out.println("outputting the phone number of incoming calls.");
							break;
						case "getContactEmails":
							System.out.println("outputting contact emails.");
							break;
						case "getContactPhones":
							System.out.println("outputting contact phones.");
							break;
						case "getContactLists":
							System.out.println("outputting contact lists.");
							break;
						case "getMessagePhones":
							System.out.println("outputting the message sender of incoming messages.");
							break;
						case "getMessageContent":
							System.out.println("outputting message lists.");
							break;
						case "getImageData":
							System.out.println("outputting image data.");
							break;
						default:
							System.out.println("User defined functions, please analyze it with PrivacyStreams Android Analyzer.");
							
					}
					System.out.println();	
				}
				
				// Find out static field reference, such as EventType.AlwaysRepeat, EventType.Off
				if (js_rOp instanceof StaticFieldRef) {
					staticFieldRef = (StaticFieldRef)js_rOp;
				}
				
				// Find out static value, such as 20.0 in setThreshold(20.0)
				if (js_rOp instanceof StaticInvokeExpr) {
					for (ValueBox vb : js_rOp.getUseBoxes()) {
						staticValueBox = vb;
					}
				}
				
				// Find out varargs, such as long...intervalOrDuration in setSamplingMode(long...intervalOrDuration)
				if (js_rOp instanceof JNewArrayExpr) {
					String mVarargLength = ((JNewArrayExpr) js_rOp).getSize().toString();
					int varargLength = Integer.parseInt(mVarargLength);
					for (int i=0; i< varargLength; i++) {
						Stmt varargs = (Stmt) unitsIterator.next();
						
						if (varargs instanceof JAssignStmt) {
							Value varargValue = ((JAssignStmt)varargs).getRightOp();
							if (varargValue instanceof Constant) {
//								tempVarargs = tempVarargs.concat(varargValue.toString());
								tempVarargs.add(varargValue.toString());
							} else {
//								tempVarargs = "<io.github.privacysecurer.core.EventType: java.lang.Long Off>";
								tempVarargs.add("<io.github.privacysecurer.core.EventType: java.lang.Long Off>");
							}
						} 
					}
				}
				
				// Find out invoke expression, such as setFieldName("avgLoudness")
				if (js_rOp instanceof VirtualInvokeExpr) {
					// Get invoked method name
					SootMethod sm = ((VirtualInvokeExpr) js_rOp).getMethod();
					
					// Add event separator, as all events started with "setField" statements
					if (sm.getName().equals("setField")) {
						System.out.println("******************");
						ArrayList<String> beginSeparator = new ArrayList<>();
						beginSeparator.add("*********");
						beginSeparator.add("*********");
						argsNameValue.add(beginSeparator);
						
						// Get event type
						if (js_rOp.getType().toString().equals(Const.Audio))
							eventType = "AudioEvent";
						if (js_rOp.getType().toString().equals(Const.Geolocation))
							eventType = "GeolocationEvent";
						if (js_rOp.getType().toString().equals(Const.Contact))
							eventType = "ContactEvent";
						if (js_rOp.getType().toString().equals(Const.Message))
							eventType = "MessageEvent";
						if (js_rOp.getType().toString().equals(Const.Image))
							eventType = "ImageEvent";
						
						System.out.println("EventType: "+eventType);
						ArrayList<String> event = new ArrayList<>();
						event.add("EventType");
						event.add(eventType);
						argsNameValue.add(event);	
					}
					
					argNameValue.add(sm.getName());
					// The SootMethod name of "build" or "longValue" doesn't meet our filtering conditions
					if (!sm.getName().equals("build") && !sm.getName().equals("longValue"))
						System.out.print(sm.getName()+": ");
					
					// Get variable value
					for (ValueBox vb : js_rOp.getUseBoxes()) {
						
						if (vb.getClass().toString().equals("class soot.jimple.internal.ImmediateBox")) {
							
							// If invoked statements contain static value (such as setThreshold(20.0)), or
							// static field reference (such as setNotificationResponsiveness(Event.ContinuousSampling)) or
							// local list variable (such as setLists(blacklist))
							if (vb.getValue() instanceof JimpleLocal) {
								
								if (staticValueBox != null) {
									System.out.print(staticValueBox.getValue()+" ");
									argNameValue.add(staticValueBox.getValue().toString());
									staticValueBox = null;
								}
								
								if (staticFieldRef != null) {
									System.out.print(staticFieldRef.getField()+" ");
									argNameValue.add(staticFieldRef.getField().toString());
									staticFieldRef = null;
								}
								
								if (tempLists != null && tempLists.length() != 0) {
									System.out.print(tempLists);
									argNameValue.add(tempLists);
									tempLists = "";
								}
								
								if (tempVarargs != null && tempVarargs.size() != 0) {
									for (String tempVararg: tempVarargs) {
										System.out.print(tempVararg+" ");
									}
//									argNameValue.add(tempVarargs);
									argNameValue.addAll(tempVarargs);
									tempVarargs.clear();
								}
							}
							
							// If invoked statements are string or numeric constants
							if ((vb.getValue() instanceof Constant) ){
								System.out.print(vb.getValue()+" ");
								argNameValue.add(vb.getValue().toString());
							} 
							
						}
					}
					
					if (!sm.getName().equals("build") && !sm.getName().equals("longValue"))
						System.out.println();
					argsNameValue.add(argNameValue);
				}
			}
		}
		
		ArrayList<String> endSeparator = new ArrayList<>();
		System.out.println("******************");
		endSeparator.add("*********");
		endSeparator.add("*********");
		argsNameValue.add(endSeparator);
	}

	public Graph build() {
		int count = 0;
		this.init();
		Util.LOGGER.info("generating PrivacyStreamsEvents analysis results");

		SootClass uqiClass = Scene.v().tryLoadClass(Const.uqiClass, SootClass.SIGNATURES);
		if (uqiClass == null) {
			Util.LOGGER.info("This is not a PrivacyStreamsEvents app.");
		}
		
		getStreamAPI = Scene.v().getMethod(Const.uqiGetStreamAPI);

		Set<SootMethod> pendingMethods = this.findPendingMethods();
		
		for (SootMethod method : pendingMethods) {
			// Used to find out event parameter settings, 
			// and store them in a ArrayList<ArrayList<String>> argsNameValue
			findAPIMethod(method);
		}
		
		for (int i=0; i<argsNameValue.size(); i++) {
			switch (argsNameValue.get(i).get(0)) {
				case "*********":
					
					if (count != 0) {
						// Template output for privacy descriptions
						System.out.println();
						System.out.println("*** The privacy description ***");
						switch (eventType) {
							case "AudioEvent":
								System.out.printf("The app checks when %s is %s %sdB.", fieldName.replace("\"", ""), comparator.replace("\"", ""), threshold.replace("\"", ""));
								System.out.println();
								break;
								
							case "GeolocationEvent":
								// fieldName is a string with quotation mark, should be removed before comparing with a variable latlon
								if (fieldName.replace("\"", "").equals("latlon")) {
									if (placeName != null) {
										System.out.printf("The app checks when the user is %s %s.", comparator.replace("\"", ""), placeName.replace("\"", ""));
										System.out.println();
									} else {
										if (comparator.replace("\"", "").equals("updated")) {
											System.out.printf("The app checks when location is updated.");
											System.out.println();
										} else {
											System.out.printf("The app checks when the user %s a geofence.", comparator.replace("\"", ""));
											System.out.println();
										}
									}
								}
								
								if (fieldName.replace("\"", "").equals("speed")) {
									System.out.printf("The app checks when speed is %s %sm/s.", comparator.replace("\"", ""), threshold.replace("\"", ""));
									System.out.println();
								}
								
								if (fieldName.replace("\"", "").equals("city")) 
									System.out.println("The app checks when the user enters a new city.");
								
								if (fieldName.replace("\"", "").equals("postcode"))
									System.out.println("The app checks when post code is updated.");
								
								if (fieldName.replace("\"", "").equals("direction"))
									System.out.println("The app checks when the user makes a turn.");
								
								if (fieldName.replace("\"", "").equals("distance")) {
									System.out.printf("The app checks when distance to destination is %s %sm.", comparator.replace("\"", ""), threshold.replace("\"", ""));
									System.out.println();
								}
								break;
								
							case "ContactEvent":
								if (fieldName.replace("\"", "").equals("caller")) {
									if (comparator.replace("\"", "").equals("from"))
										System.out.println("The app checks when caller is from a certain phone number.");
									else
										System.out.println("The app checks when caller is in a list.");
								}
								
								if (fieldName.replace("\"", "").equals("calls"))
									System.out.println("The app checks when new calls arrive.");
								
								if (fieldName.replace("\"", "").equals("emails"))
									System.out.println("The app checks when the contacts' emails are in a list.");
								
								if (fieldName.replace("\"", "").equals("contacts"))
									System.out.println("The app checks when contact lists are updated.");
								
								if (fieldName.replace("\"", "").equals("logs"))
									System.out.println("The app checks when call logs contain a record from a certain phone number.");	
								break;
								
							case "MessageEvent":
								if (fieldName.replace("\"", "").equals("sender")) {
									if (comparator.replace("\"", "").equals("from")) 
										System.out.println("The app checks when sender is from a certain phone number.");
									else
										System.out.println("The app checks when sender is in a list.");
								}
								
								if (fieldName.replace("\"", "").equals("messages"))
									System.out.println("The app checks when new messages arrive.");
								
								if (fieldName.replace("\"", "").equals("messageLists"))
									System.out.println("The app checks when text messages are updated.");
								
								break;
								
							case "ImageEvent":
								if (fieldName.replace("\"", "").equals("mediaLibrary"))
									System.out.println("The app checks when media library is updated.");
								
								if (fieldName.replace("\"", "").equals("fileOrFolder"))
									System.out.println("The app checks when the file or folder content is updated.");
								
								if (fieldName.replace("\"", "").equals("images"))
									System.out.println("The app checks when the image has a human face.");
								
								break;
							default:
								System.out.println("No matchable event type, please check it.");
						}
						
						// After executing the event, clear all variables
						optimizationConstraints.clear();
						eventType = null;
						fieldName = null;
						comparator = null;
						threshold = null; 
						latitude = null;
						longitude = null;
						radius = null;
						placeName = null;
						lists = null;
						caller = null;
						path = null;
						duration = null;
						interval = null;
						locationPrecision = null;
						recurrence = null;	
					}
					count ++;
					break;
					
				case "EventType":
					eventType = argsNameValue.get(i).get(1);
					break;
				case "setField":
					fieldName = argsNameValue.get(i).get(1);
					break;
				case "setComparator":
					comparator = argsNameValue.get(i).get(1);
					break;
				case "setFieldConstraints":
					threshold = argsNameValue.get(i).get(1);
					break;
				case "setLatitude":
					latitude = argsNameValue.get(i).get(1);
					break;
				case "setLongitude":
					longitude = argsNameValue.get(i).get(1);
					break;
				case "setRadius":
					radius = argsNameValue.get(i).get(1);
					break;
				case "setPlaceName":
					placeName = argsNameValue.get(i).get(1);
					break;
				case "setContactList":
					lists = argsNameValue.get(i).get(1);
					break;
				case "setPhoneNumber":
					caller = argsNameValue.get(i).get(1);
					break;
				case "setPath":
					path = argsNameValue.get(i).get(1);
					break;
				case "setSamplingMode":
					if (eventType.equals("AudioEvent")) {
						if (argsNameValue.get(i).size() == 2)
							duration = argsNameValue.get(i).get(1);
						if (argsNameValue.get(i).size() == 3) {
							interval = argsNameValue.get(i).get(1);
							duration = argsNameValue.get(i).get(2);
						}
					}
					if (eventType.equals("GeolocationEvent")) {
						if (argsNameValue.get(i).size() == 2) 
							interval = argsNameValue.get(i).get(1);
						if (argsNameValue.get(i).size() == 3) {
							interval = argsNameValue.get(i).get(1);
							locationPrecision = argsNameValue.get(i).get(2);
						}
					}
					break;	
//				case "setDuration":
//					duration = argsNameValue.get(i).get(1);
//					break;
//				case "setInterval":
//					interval = argsNameValue.get(i).get(1);
//					break;
				case "setLocationPrecision":
					locationPrecision = argsNameValue.get(i).get(1);
					break;
				case "setNotificationResponsiveness":
					recurrence = argsNameValue.get(i).get(1);
					break;
				case "addOptimizationConstraints":
					for (int j=1; j<argsNameValue.get(i).size(); j++)
						optimizationConstraints.add(argsNameValue.get(i).get(j));
					break;
				default:
					break;
			}
		}
		
		Util.LOGGER.info("finished analyzing PrivacySecurer");
		return null;
	}
}


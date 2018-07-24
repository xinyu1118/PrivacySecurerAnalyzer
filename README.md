# PrivacySecurerAnalyzer


---

PrivacyStreamsEvents is a programming framework for handling personal data access events in an privacy-friendly way. It provides easy-to-use Android APIs for processing various types of personal data access scenarios with a uniform query interface.

Based on the functions used in the query, PrivacyStreamsEvents is able to **generate a privacy description about what granularity of data are accessed and when** using PrivacySecurerAnalyzer, which could be used for the app description or privacy policy. 

###How to use **PrivacySecurerAnalyzer**:

1). Generate your apk file

e.g. Android Studio Build -> Build APK(s) -> generate apps without signature, 
file path: project/app/build/outputs/apk/debug/app-debug.apk

2). Configure input and output parameters

args illustration:

    Missing required options: i, o
    usage: PrivacySecurerAnalyzer -i <directory/file> -o <directory> [-f <frontend>] [-b <backend>] [-h] [-quiet] [-debug]
    -i,--input <directory/file>   path to target program
    -o,--output <directory>       path to output dir
    -f,--frontend <frontend>      DERG frontend: apk
    -b,--backend <backend>        DERG backend: graph_export
    -h,--help                     print this help message
    -quiet                        be extra quiet
    -debug                        print debug information


Eclipse Run -> Run Configurations -> Arguments, e.g.
 **PrivacySecurerAnalyzer -i /Users/xinyuyang/Desktop/app-debug.apk -o /Users/xinyuyang/Desktop/output -sdk /Users/xinyuyang/Library/Android/sdk**

3). Run and get analysis results on the console, including:

 - The built-in function name, input and output; 
 - Event parameter settings, including function name and parameters;
 - The privacy description.


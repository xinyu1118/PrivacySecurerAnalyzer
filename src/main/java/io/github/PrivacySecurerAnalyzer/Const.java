package io.github.PrivacySecurerAnalyzer;

public class Const {
	public static String psPackage = "io.github.privacystreamsevents";
    public static String uqiClass = "io.github.privacystreamsevents.core.UQI";
    public static String uqiGetStreamAPI = "<io.github.privacystreamsevents.core.UQI: void addEventListener(io.github.privacystreamsevents.core.EventType,io.github.privacystreamsevents.core.EventCallback)>";
    
    public static String Audio = "io.github.privacystreamsevents.core.AudioEvent$AudioEventBuilder";
    public static String Geolocation = "io.github.privacystreamsevents.core.GeolocationEvent$GeolocationEventBuilder";
    public static String Contact = "io.github.privacystreamsevents.core.ContactEvent$ContactEventBuilder";
    public static String Message = "io.github.privacystreamsevents.core.MessageEvent$MessageEventBuilder";
    public static String Image = "io.github.privacystreamsevents.core.ImageEvent$ImageEventBuilder";
    
    public static String EventAlwaysRepeat = "<io.github.privacystreamsevents.core.EventType: java.lang.Integer AlwaysRepeat>";
    public static String EventOff = "<io.github.privacystreamsevents.core.Event: java.lang.Long Off>";
     
//    public static String psPackage = "io.github.privacystreams";
//    public static String uqiClass = "io.github.privacystreams.core.UQI";
//    public static String uqiGetStreamAPI = "<io.github.privacystreams.core.UQI: io.github.privacystreams.core.PStream getData(io.github.privacystreams.core.PStreamProvider,io.github.privacystreams.core.purposes.Purpose)>";
}

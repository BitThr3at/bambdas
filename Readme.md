# Burp Bambdas Cheatsheet

DetectCORS.bambda
```java
/**
 * Check the CORS vulnerability
 * @author https://github.com/JaveleyQAQ/
 **/

if (requestResponse.hasResponse() && requestResponse.request().hasHeader("Origin") && requestResponse.response().hasHeader("Access-Control-Allow-Origin"))
{  
    var requestOrigin = requestResponse.request().headerValue("Origin");
    var responseOrigin = requestResponse.response().headerValue("Access-Control-Allow-Origin");
    return requestOrigin.equals(responseOrigin) ? Character.toString(0x2757).concat("CORS?") : responseOrigin;
    
} else {
    return "";
}
```

JWTAlgorithm.bambda
```java
/**
 * Extracts the JWT alg value from JWT session Cookies
 * @author trikster
 **/

if (!requestResponse.finalRequest().hasParameter("session", HttpParameterType.COOKIE)) {
    return "";
}

var cookieValue = requestResponse.finalRequest().parameter("session", HttpParameterType.COOKIE).value();

var jwtFrags = cookieValue.split("\\.");

if (jwtFrags.length != 3 ) {
    return "";
}

var headerJson = utilities().base64Utils().decode(jwtFrags[0], Base64DecodingOptions.URL);
var matcher = Pattern.compile(".+?\"alg\":\"(\\w+)\".+").matcher(headerJson.toString());

return matcher.matches() ? matcher.group(1) : "";
```

Referer.bambda
```java
/**
 * Extracts Referer request header.
 *
 * Useful to identify sensitive data leakage via Referer header like
 * OIDC authorization codes.
 *
 * @author emanuelduss
 **/

return requestResponse.request().hasHeader("Referer") ? requestResponse.request().headerValue("Referer") : "";
```

SOAPMethod.bambda
```java
/**
 * Extracts the Method and an example value from a SOAP Request
 * @author Nick Coblentz (https://github.com/ncoblentz)
 *
 * Currently extracts the soap method and the WS-Security Username field's value. 
 * Assumes the body tag's namespace is "s" as in `<s:Body`, customize if your SOAP request tags don't match
 * Customize by adding additional RegEx's to extract more content
 **/

if(requestResponse.request().hasHeader("Content-Type")
    && requestResponse.request().headerValue("Content-Type").contains("soap+xml"))
{
    StringBuilder builder = new StringBuilder();
    if(requestResponse.request().bodyToString().contains("<s:Body"))
    {        
        Matcher m = Pattern.compile("<(?:[a-zA-Z0-9]+:)?Username>([^<]+)</(?:[a-zA-Z0-9]+:)*Username>|<(?:[a-zA-Z0-9]+:)*Body[^>]*><([^ ]+)",Pattern.CASE_INSENSITIVE).matcher(requestResponse.request().bodyToString());
        while(m.find() && m.groupCount()>0) {
            for(int i=1;i<=m.groupCount();i++) {
                if(m.group(i)!=null)
                    builder.append(m.group(i)+" ");
            }
        }
        return builder.toString();
    }
}
return "";
```

ServerHeader.bambda
```java
/**
 * Extracts the value of the Server header from the response
 * @author agarri_fr
 **/

return requestResponse.hasResponse() && requestResponse.response().hasHeader("Server")
  ? requestResponse.response().headerValue("Server")
  : "";
```

WCFBinarySOAPMethod.bambda
```java
/**
 * Extracts the WCF SOAP Binary Method from the Request
 * @author Nick Coblentz (https://github.com/ncoblentz)
 * 
 * You need to customize the `prefix` parameter below to match the namespace reflected for the application you are testing
 **/

if(requestResponse.request().hasHeader("Content-Type") && requestResponse.request().headerValue("Content-Type").equals("application/soap+msbin1")){
    String body = requestResponse.request().bodyToString();
    String prefix = "www.examplewebsite.com/xmlnamespace/";
    int start = body.indexOf(prefix);
    if(start>0)
    {
        int end = body.indexOf("@",start+prefix.length());
        if(end>0)
        {
            return body.substring(start+prefix.length(), end);
        }

    }        
}
return "";
```

HighlightToolType.bambda
```java
/**
 * Highlights messages according to their tool type.
 * @author ps-porpoise
**/
var highlights = Map.of(
        ToolType.TARGET,     HighlightColor.RED,
        ToolType.PROXY,      HighlightColor.BLUE,
        ToolType.INTRUDER,   HighlightColor.CYAN,
        ToolType.REPEATER,   HighlightColor.MAGENTA,
        ToolType.EXTENSIONS, HighlightColor.ORANGE,
        ToolType.SCANNER,    HighlightColor.GREEN,
        ToolType.SEQUENCER,  HighlightColor.PINK
);

requestResponse.annotations().setHighlightColor(
        highlights.getOrDefault(requestResponse.toolSource().toolType(), HighlightColor.NONE)
);

return true;
```

SlowResponses.bambda
```java
/**
 * Finds slow responses.
 * @author ps-porpoise
**/
var delta = requestResponse.timingData().timeBetweenRequestSentAndStartOfResponse();
var threshold = Duration.ofSeconds(3);

return delta != null && delta.toMillis() >= threshold.toMillis();
```

AnnotateSoapRequests.bambda
```java
/**
 * This script populates elements of the SOAP request in the "Notes" column of Burp's Proxy History. You can expand upon the capture groups by editing the RegEx pattern.
 *
 * @author Nick Coblentz (https://github.com/ncoblentz)
 * 
 **/

// Only applies to in-scope requests, feel free to remove this part of the if statement if you want it to apply to all requests
if(requestResponse.request().isInScope()
    && !requestResponse.annotations().hasNotes() //don't apply it if notes are already present
    && requestResponse.request().hasHeader("Content-Type")
    && requestResponse.request().headerValue("Content-Type").contains("soap+xml")) //look for soap requests
{
    StringBuilder builder = new StringBuilder();
    if(requestResponse.request().bodyToString().contains("<s:Body"))
    {
        //Currently looks for the tag just after body and for any usernames in the ws-security header. You can add more of your own here.
        Matcher m = Pattern.compile("<(?:[a-zA-Z0-9]+:)?Username>([^<]+)</(?:[a-zA-Z0-9]+:)*Username>|<(?:[a-zA-Z0-9]+:)*Body[^>]*><([^ ]+)",Pattern.CASE_INSENSITIVE).matcher(requestResponse.request().bodyToString());

        while(m.find() && m.groupCount()>0) {
            for(int i=1;i<=m.groupCount();i++) {
                if(m.group(i)!=null)
                    builder.append(m.group(i)+" ");
            }
        }
        requestResponse.annotations().setNotes(builder.toString());
    }
}

// Put your typical filters here, this one doesn't actually filter anything
return true;
```

Detect101SwitchingProtocols.bambda
```java
/**
 * Bambda Script to Detect "101 Switching Protocols" in HTTP Response
 * @author Tur24Tur / BugBountyzip (https://github.com/BugBountyzip)
 * It identifies if the HTTP response status code is 101 (Switching Protocols).
 **/

// Ensure there is a response and check if the status code is 101
return requestResponse.hasResponse() && requestResponse.response().statusCode() == 101;
```

DetectServerNames.bambda
```java
/**
 * Bambda Script to Detect Specific Server Names in HTTP Response
 * @author Tur24Tur / BugBountyzip (https://github.com/BugBountyzip)
 * It identifies if the 'Server' header of the HTTP response contains any of the specified server names.
 * Upon detection, responses are highlighted in red and notes are appended, if enabled.
 **/

// Configuration setting for manual annotations
boolean enableManualAnnotations = true;

Set<String> serverNames = Set.of(
    "awselb", "Kestrel", "Apache", "Nginx", "Microsoft-IIS", "LiteSpeed", "Google Frontend", 
    "GWS", "openresty", "IBM_HTTP_Server", "AmazonS3", "CloudFront", "AkamaiGHost", "Jetty", 
    "Tengine", "lighttpd", "AOLserver", "ATS", "Boa", "Caddy", "Cherokee", "Caudium", "Hiawatha", 
    "GlassFish", "H2O", "httpd", "Jigsaw", "Mongrel", "NCSA HTTPd", "Netscape Enterprise", 
    "Oracle iPlanet", "Pound", "Resin", "thttpd", "Tornado", "Varnish", "WebObjects", "Xitami", 
    "Zope", "Werkzeug", "WebSTAR", "WebSEAL", "WebServerX", "WebtoB", "Squid", "Sun ```java System Web Server", 
    "Sun ONE Web Server", "Stronghold", "Zeus Web Server", "Roxen", "RapidLogic", "Pramati", 
    "Phusion Passenger", "Oracle Containers for J2EE", "Oracle-Application-Server-10g", "Oracle-Application-Server-11g", 
    "Nostromo", "Novell-HTTP-Server", "NaviServer", "MochiWeb", "Microsoft-HTTPAPI", "Mbedthis-Appweb", 
    "Lotus-Domino", "Kangle", "Joost", "Jino", "IceWarp", "GoAhead", 
    "Flywheel", "EdgePrism", "DMS", "Cowboy", "CommuniGatePro", "CompaqHTTPServer", "CERN", "CauchoResin", 
    "BarracudaHTTP", "BaseHTTP", "AllegroServe", "Abyss", "4D_WebSTAR_S", "4D_WebSTAR_D", 
    "Yaws", "WDaemon", "Virtuoso", "UserLand", "TUX", "TwistedWeb", "Thin", 
    "Thttpd", "Swiki", "SurgeLDAP", "Sun-ONE-Web-Server", "Sun-ONE-Application-Server", 
    "Sucuri/Cloudproxy", "SSWS", "SWS", "SW", "srv", "squid", "Spamfire", "SOMA", 
    "Snap", "SmugMug", "SME Server", "Smart-4-Hosting", "Sioux", "SilverStream", "Silk", "Siemens Gigaset WLAN Camera"
);

// Ensure there is a response
if (!requestResponse.hasResponse()) {
    return false;
}

// Get the 'Server' header from the response
String serverHeader = requestResponse.response().headerValue("Server");

// Check if the 'Server' header value is in the set of server names
boolean foundServerName = serverHeader != null && serverNames.contains(serverHeader);
if (foundServerName && enableManualAnnotations) {
    requestResponse.annotations().setHighlightColor(HighlightColor.RED);
    requestResponse.annotations().setNotes("Detected '" + serverHeader + "' in 'Server' header");
}

return foundServerName;
```

DetectSuspiciousJSFunctions.bambda
```java
/**
 * Bambda Script to Detect and Highlight Suspicious ```javaScript Functions
  @author Tur24Tur / BugBountyzip (https://github.com/BugBountyzip)
  It identifies a range of suspicious ```javaScript functions often associated with unsafe practices or vulnerabilities.
 * Upon detection, responses are highlighted in red and notes are appended, if enabled.
 **/

boolean enableManualAnnotations = true;

// Ensure there is a response
if (!requestResponse.hasResponse()) {
    return false;
}

// Check the Content-Type header for ```javaScript
String contentType = requestResponse.response().headerValue("Content-Type");
if (contentType == null || !contentType.toLowerCase().contains("application/```javascript")) {
    return false;
}

String responseBody = requestResponse.response().bodyToString();
boolean foundSuspiciousFunction = false;
StringBuilder notesBuilder = new StringBuilder();

// Expanded list of suspicious ```javaScript functions
String[] suspiciousFunctions = {
    "eval\\(",                 // Executes a string as code
    "setTimeout\\(",           // Can execute strings as code if used improperly
    "setInterval\\(",          // Similar to setTimeout, can execute strings as code
    "document\\.write\\(",     // Can overwrite entire document
    "innerHTML",               // Can introduce XSS vulnerabilities if used with untrusted content
    "document\\.createElement\\(",  // Safe, but part of dynamic content generation which can be risky
    "document\\.execCommand\\(",   // Deprecated, was used to execute certain commands
    "document\\.domain",       // Altering the document.domain can be risky
    "window\\.location\\.href",    // Can be used for redirects which might be used in phishing
    "document\\.cookie",       // Accessing cookies can be sensitive
    "document\\.URL",          // Can be used to extract URL information
    "document\\.referrer",     // Can be used to check where the request came from
    "window\\.open\\(",        // Opening a new window or tab, potential for misuse
    "document\\.body\\.innerHTML", // Specific case of innerHTML, also risky
    "element\\.setAttribute\\(",   // If used improperly, can set risky attributes like 'onclick'
    "element\\.outerHTML",         // Similar risks to innerHTML
    "XMLHttpRequest\\(",           // Can be used for sending/receiving data, potential for misuse
    "fetch\\(",                    // Modern way to make network requests, potential for misuse
    "navigator\\.sendBeacon\\("    // Used to send analytics and tracking data
};

for (String function : suspiciousFunctions) {
    Pattern pattern = Pattern.compile(function);
    Matcher matcher = pattern.matcher(responseBody);
    if (matcher.find()) {
        foundSuspiciousFunction = true;
        if (enableManualAnnotations) {
            if (notesBuilder.length() > 0) {
                notesBuilder.append(", ");
            }
            notesBuilder.append(function); // Append the complete function signature
        }
    }
}

if (foundSuspiciousFunction && enableManualAnnotations) {
    requestResponse.annotations().setHighlightColor(HighlightColor.RED);
    if (notesBuilder.length() > 0) {
        requestResponse.annotations().setNotes("Suspicious JS functions detected: " + notesBuilder.toString());
    }
}

return foundSuspiciousFunction;
```

EmailHighlighter.bambda
```java
/**
 * Script to Filter Out Email Addresses in Responses and Highlight Them if Found
 * @author Tur24Tur / BugBountyzip (https://github.com/BugBountyzip)
 **/

boolean manualColorHighlightEnabled = true;

// Set of file extensions to ignore
Set<String> ignoredExtensions = Set.of("mp4", "mp3", "png", "gif", "jpg", "jpeg", "css", "pdf");

if (!requestResponse.hasResponse()) {
    return false;
}

// Retrieve the URL from the request part of the requestResponse object
String requestUrl = requestResponse.request().url().toString();


for (String ext : ignoredExtensions) {
    // Check if the URL ends with any of the ignored file extensions
    if (requestUrl.toLowerCase().endsWith("." + ext)) {
        return false; 
    }
}

// Extract the response body as a string and remove any leading and trailing whitespace
var body = requestResponse.response().bodyToString().trim();


String emailRegexPattern = "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.(?!jpeg|png|jpg|gif|webp)[A-Z|a-z]{2,7}\\b";
Pattern emailPattern = Pattern.compile(emailRegexPattern);

// Create a matcher to find email addresses in the response body
Matcher emailMatcher = emailPattern.matcher(body);
if (emailMatcher.find()) { 
    if (manualColorHighlightEnabled) { 

        requestResponse.annotations().setHighlightColor(HighlightColor.GREEN);
        // Add a note indicating that an email was found
        requestResponse.annotations().setNotes("Email Found!: " + emailMatcher.group());
    }
    return true; 
}


return false;
```

FilterAuthenticated.bambda
```java
/**
 * Filters authenticated 200 OK requests in Proxy HTTP history. See four config values below.
 *
 * @author joe-ds (https://github.com/joe-ds)
 **/

var configNoFilter = true;        // If set to false, won't show JS, GIF, JPG, PNG, CSS.
var configNotInScopeOnly = true;  // If set to false, won't show out-of-scope items.
var sessionCookieName = "";       // If given, will look for a cookie with that name.
var sessionCookieValue = "";      // If given, will check if cookie with sessionCookieName has this value.

if (!requestResponse.hasResponse()) {
    return false;
}

var request = requestResponse.request();
var response = requestResponse.response();

if (!response.isStatusCodeClass(StatusCodeClass.CLASS_2XX_SUCCESS)) {
    return false;
}

var authHeader = request.hasHeader("Authorization");

boolean sessionCookie = request.headerValue("Cookie") != null
                            && !sessionCookieName.isEmpty()
                            && request.hasParameter(sessionCookieName, HttpParameterType.COOKIE) 
                            && (sessionCookieValue.isEmpty() || sessionCookieValue.equals(request.parameter(sessionCookieName, HttpParameterType.COOKIE).value()));

var path = request.pathWithoutQuery().toLowerCase();
var mimeType = requestResponse.mimeType();
var filterDenyList = mimeType != MimeType.CSS
 && mimeType != MimeType.IMAGE_UNKNOWN
 && mimeType != MimeType.IMAGE_JPEG
 && mimeType != MimeType.IMAGE_GIF
 && mimeType != MimeType.IMAGE_PNG
 && mimeType != MimeType.IMAGE_BMP
 && mimeType != MimeType.IMAGE_TIFF
 && mimeType != MimeType.UNRECOGNIZED
 && mimeType != MimeType.SOUND
 && mimeType != MimeType.VIDEO
 && mimeType != MimeType.FONT_WOFF
 && mimeType != MimeType.FONT_WOFF2
 && mimeType != MimeType.APPLICATION_UNKNOWN
 && !path.endsWith(".js")
 && !path.endsWith(".gif")
 && !path.endsWith(".jpg")
 && !path.endsWith(".png")
 && !path.endsWith(".css");

return (authHeader || sessionCookie) && (configNoFilter || filterDenyList) && (configNotInScopeOnly || request.isInScope());
```

FilterAuthenticatedNonBearerTokens.bambda
```java
/**
 * Filter when an Authorization header is present, not empty and does not include a traditional bearer token (beginning with "ey")
 *
 * @author GangGreenTemperTatum (https://github.com/GangGreenTemperTatum)
 **/

var configInScopeOnly = true; // If set to true, won't show out-of-scope items
var sessionCookieName = ""; // If given, will look for a cookie with that name.
var sessionCookieValue = ""; // If given, will check if cookie with sessionCookieName has this value.

var request = requestResponse.request();
var response = requestResponse.response();

if (configInScopeOnly && !request.isInScope()) {
    return false;
}

if (!requestResponse.hasResponse() || !response.isStatusCodeClass(StatusCodeClass.CLASS_2XX_SUCCESS)) {
    return false;
}

var hasAuthHeader = request.hasHeader("Authorization");
var authHeaderValue = hasAuthHeader ? String.valueOf(request.headerValue("Authorization")).toLowerCase() : null;

if (!hasAuthHeader || (authHeaderValue == null || authHeaderValue.isEmpty())) {
    return false;
}

var excludeAuthorization =
    authHeaderValue.contains("bearer") &&
    authHeaderValue.contains("ey");

var sessionCookie = request.headerValue("Cookie") != null &&
    !sessionCookieName.isEmpty() &&
    request.hasParameter(sessionCookieName, HttpParameterType.COOKIE) &&
    (sessionCookieValue.isEmpty() || sessionCookieValue.equals(String.valueOf(request.parameter(sessionCookieName, HttpParameterType.COOKIE).value())));

return !excludeAuthorization || sessionCookie;
```

FilterHighlightAnnotateOWASP.bambda
```java
/**
* Filters Proxy HTTP history for requests with vulnerable parameters based on the OWASP Top 25
* using the parameter arrays written by Tur24Tur / BugBountyzip (https://github.com/BugBountyzip).
* @author Shain Lakin (https://github.com/flamebarke/SkittlesBambda)
* Implements colour highlighting for each class of vulnerability along with
* automatic note annotations detailing the parameter to test and class of vulnerability.
**/

// Define vulnerable parameter group record
record VulnParamGroup(String title, HighlightColor color, String... parameterNames) {}

// Vulnerable Parameter Groups
VulnParamGroup ssrf = new VulnParamGroup("SSRF", HighlightColor.GREEN, "dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir");
VulnParamGroup sql = new VulnParamGroup("SQL", HighlightColor.BLUE, "id", "page", "report", "dir", "search", "category", "file", "class", "url", "news", "item", "menu", "lang", "name", "ref", "title", "view", "topic", "thread", "type", "date", "form", "main", "nav", "region");
VulnParamGroup xss = new VulnParamGroup("XSS", HighlightColor.ORANGE, "q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p", "month", "image", "list_type", "url", "terms", "categoryid", "key", "l", "begindate", "enddate");
VulnParamGroup lfi = new VulnParamGroup("LFI", HighlightColor.YELLOW, "cat", "dir", "action", "board", "date", "detail", "file", "download", "path", "folder", "prefix", "include", "page", "inc", "locate", "show", "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf");
VulnParamGroup or = new VulnParamGroup("OR", HighlightColor.PINK, "next", "url", "target", "rurl", "dest", "destination", "redir", "redirect_uri", "redirect_url", "redirect", "out", "view", "to", "image_url", "go", "return", "returnTo", "return_to", "checkout_url", "continue", "return_path");
VulnParamGroup rce = new VulnParamGroup("RCE", HighlightColor.RED, "cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "feature", "exe", "module", "payload", "run", "print");

// Toggle for highlighting
boolean highlightEnabled = true;

// Set multi vulnerable parameter group colour
HighlightColor multipleVulnColor = HighlightColor.MAGENTA;
VulnParamGroup[] groups = {ssrf, sql, xss, lfi, or, rce};
Set<String> foundParams = new HashSet<>();
Map<HighlightColor, Integer> colorCounts = new HashMap<>();
String combinedNotes = "";

// Get the request object
var request = requestResponse.request();

// Main loop to check for matches
for (VulnParamGroup group : groups) {
    for (String paramName : group.parameterNames()) {
        if (request.hasParameter(paramName, HttpParameterType.URL) ||
            request.hasParameter(paramName, HttpParameterType.BODY)) {
            if (highlightEnabled) {
                foundParams.add(group.title() + ": " + paramName);
                colorCounts.put(group.color(), colorCounts.getOrDefault(group.color(), 0) + 1);
            }
            // Return if only one vulnerability class applies
            if (!highlightEnabled) {
                requestResponse.annotations().setHighlightColor(group.color());
                return true;
            }
        }
    }
}

// If more than one vulnerability class applies set the multi vulnerable parameter colour
if (!foundParams.isEmpty()) {
    HighlightColor highlightColor = multipleVulnColor;
    if (colorCounts.size() == 1) {
        highlightColor = colorCounts.keySet().iterator().next();
    }
    
    requestResponse.annotations().setHighlightColor(highlightColor);
    combinedNotes = String.join(", ", foundParams);
    requestResponse.annotations().setNotes(combinedNotes);
    return true;
}

return false;
```

FilterOnCookieValue.bambda
```java
/**
 * Filters Proxy HTTP history for requests with a specific Cookie value.
 *
 * @author LostCoder
 **/

if (requestResponse.request().hasParameter("foo", HttpParameterType.COOKIE)) {
    var cookieValue = requestResponse
        .request()
        .parameter("foo", HttpParameterType.COOKIE)
        .value();

    return cookieValue.contains("1337");
}

return false;
```

FilterOnSpecificHighlightColor.bambda
```java
/**
 * Filters requests/responses for specific highlight colors
 *
 * @author Nick Coblentz (https://github.com/ncoblentz)
 * 
 * You can currently filter requests/responses that are highlighted, but you can't ask Burp to show you requests/responses highlighted with a particular color only. If you use a specific color to categorize requests/responses for role-based authorization testing, todo lists, or identifying a particular browser tab/window then its helpful to be able to see only those requests/resposnse you are interested in. The following Bambda snippet lets you choose the color(s) you want to see. The available colors are:
 * Options:
 * - HighlightColor.BLUE;
 * - HighlightColor.CYAN;
 * - HighlightColor.GRAY;
 * - HighlightColor.GREEN;
 * - HighlightColor.MAGENTA;
 * - HighlightColor.NONE;
 * - HighlightColor.ORANGE;
 * - HighlightColor.PINK;
 * - HighlightColor.RED;
 * - HighlightColor.YELLOW;
 **/

 return requestResponse.annotations().highlightColor().equals(HighlightColor.CYAN);
```

FilterOutOptionsRequests.bambda
```java
/**
 * Filter out OPTIONS requests.
 *
 * @author Trikster
 **/

return !requestResponse.request().method().equals("OPTIONS");
```

FindJSONresponsesWithIncorrectContentType.bambda
```java
/**
 * Finds JSON responses with wrong Content-Type
 *
 * The content is probably json but the content type is not application/json
 *
 * @author albinowax
 **/

var contentType = requestResponse.hasResponse() ? requestResponse.response().headerValue("Content-Type") : null;

if (contentType != null && !contentType.contains("application/json")) {
 String body = requestResponse.response().bodyToString().trim();

 return body.startsWith( "{" ) || body.startsWith( "[" );
}

return false;
```

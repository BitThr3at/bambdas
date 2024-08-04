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

Specific Cookie Value
```java
/*
  Author: PortSwigger (https://portswigger.net)
  Source:  PortSwigger Blog (https://portswigger.net/blog/introducing-bambdas)
  Init Pub. Date: Nov 14, 2023
  Use Case: 
    Filter for requests with a specific cookie value.
*/

var request = requestResponse.request();
var cookie = request.parameter("foo", HttpParameterType.COOKIE);

cookie != null && cookie.value().conatins("1337");
```

Cachable Responses
```java
/*
  Author: 0x999 (https://x.com/_0x999/)
  Source:  X/Twitter (https://x.com/_0x999/status/1727072149058535791/photo/2)
  Init Pub. Date: Nov 22, 2023
  Use Case: 
    Filter for responses that contain Cache header to probe for Cache-Poisioning vulnerabilities.
*/

if(!requestResponse.hasResponse())) {
  return false;
}

var headers = requestResponse.response().headers();

for (var header : headers) {
 if (header.name().toLowerCase().contains("cache") &&
    (header.value().toLowerCase().contains("hit") || 
    header.value().toLowerCase().contains("miss"))) {
    return true;
  }
}
     
return false;
```

Incorrect Content-Length
```java
/*
  Author: James Kettle (https://x.com/albinowax)
  Source: X (Twitter)
  Init Pub. Date: Oct 17, 2023
  Use Case: 
    Filter for responses with incorrect Content-Length.
*/

if(!requestResponse.hasResponse() || requestResponse.response().hasHeader("Content-Length")) {
  return false;
}

int declaredContentLength = Integer.parseInt(requestResponse.response().headerValue("Content-Length"));
int realContentLength = requestResponse.response().body().length();

return declaredContentLength != realContentLength;
```


JSON Filter
```java
/*
  Author: Gareth Heyes (https://x.com/garethheyes)
  Source: X (Twitter)
  Init Pub. Date: Oct 18, 2023
  Use Case: 
    Filter for JSON endpoints with an empty or text/html MIME-type
*/

if(!requestResponse.hasResponse()) {
  return false;
}

if(requestResponse.response().hasHeader("Content-Type")) {
  if(!requestResponse.response().headerValue("Content-Type").contains("text/html")) {
    return false;
  }
}

String body = requestResponse.response().bodyToString().trim();
boolean looksLikeJson = body.startsWith("{") || body.startsWith("[");

if(!looksLikeJson) {
  return false;
}

return true;
```

JSON with Content-Type Mismatch
```java
/*
  Author: PortSwigger (https://portswigger.net)
  Source:  PortSwigger Blog (https://portswigger.net/blog/introducing-bambdas)
  Init Pub. Date: Nov 14, 2023
  Use Case: 
    Filter for responses with JSON body but wrong content-type header value set.
*/

var contentType = requestResponse.response().headerValue("Content-Type");

if (contentType != null && !contentType.contains("application/json")) {
    String body = requestResponse.response().bodyToString().trim();

    return body.startsWith( "{" ) || body.startsWith( "[" );
}

return false;

```

JavaScript Files via Content-Type
```java
/*
  Author: Tolgaha (https://x.com/TolgaDemirayak)
  Source:  X/Twitter (https://x.com/TolgaDemirayak/status/1727074336056783190/)
  Init Pub. Date: Nov 22, 2023
  Use Case: 
    Filter for responses that contain JavaScript based on content-type header value.
*/

if (!requestResponse.request().isInScope()) {
  return false;
}

var contentTypeValue = requestResponse.response().headerValue("Content-Type");

if (contentTypeValue != null) {
   if (contentTypeValue.contains("application/javascript") &&
     contentTypeValue.contains("text/javascript") &&
     contentTypeValue.contains("application/x-javascript")) {
       return false;
   }
}

return true;
```

Potential Open Redirects 302 Based
```java
/*
  Author: / XNL -н4cĸ3r (https://x.com/xnl_h4ck3r)
  Source:  X/Twitter (https://x.com/xnl_h4ck3r/status/1724812731008631187/photo/1)
  Init Pub. Date: Nov 22, 2023
  Use Case: 
    Filter for responses that redirect to probe for Open Redirection vulnerabilities.
  Addl. Info:
    - If a 302 response has a large body, it could have something useful in there
    and also potentially be bypassed by matching and replacing "302 Found" with
    "200 OK" and removing "Location" header from the request.
    - Reason for counting hrefs: A normal 302 often has a href to the redirect page
    in case it doesn't redirect. If there's more than 1 href, there's probably other
    interesting content. It's an extra check just in case the content length is still
    lower than the value we're looking for.
*/

if(!requestResponse.hasResponse() && requestResponse.response().statusCode() != 302) {
  return false;
}

var response = requestResponse.response();
var bodyLength = response.body().toString().toLowerCase().replaceAll("<a.*</a>", "").length();
var numberofHrefs =  response.body().countMatches("href=", false);

return (bodyLength > 1000 || numberOfHrefs > 1);
```

Redirection with Cookie
```java
/*
  Author: PortSwigger (https://portswigger.net)
  Source: PortSwigger Docs (https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history/bambdas)
  Init Pub. Date: Oct 20, 2023
  Use Case: 
    Filter for responses that have a 3XX status code and a cookie set with the name session.
*/

if (!requestResponse.hasResponse()) {
    return false;
}

var response = requestResponse.response();
return response.isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION) && response.hasCookie("session");

```

Role Claim in JWT
```java
/*
  Author: PortSwigger (https://portswigger.net)
  Source:  PortSwigger Blog (https://portswigger.net/blog/introducing-bambdas)
  Init Pub. Date: Nov 14, 2023
  Use Case: 
    Filter for responses with a custom claim - role in a JWT token.
*/

var body = requestResponse.response().bodyToString().trim();

if (requestResponse.response().hasHeader("authorization")) {
    var authValue = requestResponse.response().headerValue("authorization");

    if (authValue.startsWith("Bearer ey")) {
        var tokens = authValue.split("\\.");

        if (tokens.length == 3) {
            var decodedClaims = utilities().base64Utils().decode(tokens[1], Base64DecodingOptions.URL).toString();

            return decodedClaims.toLowerCase().contains("role");
        }
    }
}

return false;
```

UID for RCE
```java
/*
  Author: Miguel J. Carmona (https://x.com/mibaltoalexTolgaDemirayak)
  Source:  X/Twitter (https://x.com//mibaltoalex/status/1728066917875732957/)
  Init Pub. Date: Nov 24, 2023
  Use Case: 
    Filter for JSON responses that contain uid key/property to probe for RCE vulnerability.
*/

if(requestResponse.mimeType().equals(MimeType.JSON)) {
  return this.utilities().htmlUtils().decode(requestResponse.response().bodyToString()).contains("uid");
}

return true;
```

Coloring
```java
/*
  Author: rtfmkiesel (https://github.com/rtfmkiesel)
  Source: GitHub
  Init Pub. Date: Nov 30, 2023
  Use Case: 
    Color response based on certain conditions
*/

/*
  if (YOUR CONDITION) {
    requestResponse.annotations().setHighlightColor(HighlightColor.<YOUR COLOR>);
  }
*/

// Example: Status Code
// Make all client errors blue
if (response.isStatusCodeClass(StatusCodeClass.CLASS_4XX_CLIENT_ERRORS)) {
	requestResponse.annotations().setHighlightColor(HighlightColor.BLUE);
}
// Make all server errors red
if (response.isStatusCodeClass(StatusCodeClass.CLASS_5XX_SERVER_ERRORS)) {
	requestResponse.annotations().setHighlightColor(HighlightColor.RED);
}
```

Open-redirects
```java
/*
  Author: https://github.com/0x999-x/burpsuite-bambdas
  Source: GitHub
  Use Case: 
    Checks any response with a 3xx response code, if the request contains parameters and they are of type URL and start with (http|https|//) the filter will check if the response's location header matches the parameter value and return true if it does
*/
if (!requestResponse.hasResponse()) {
  return false;
}
var response = requestResponse.response();
if (response.isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)) {
  var parameters = requestResponse.request().parameters();
  for (var param : parameters) {
    if (param.type() != HttpParameterType.URL) {
      return false;
    }
    var decodedParam = utilities().urlUtils().decode(param.value()).toLowerCase();
    if (decodedParam.startsWith("http") || decodedParam.startsWith("https") || decodedParam.startsWith("//")) {
      var LocationValue = requestResponse.response().headerValue("Location").toLowerCase();
      if (LocationValue.startsWith(decodedParam)) {
        return true;
      }
    }
  }
}
return false;
```

Create a wordlist of unique parameters
```java
/*
  Author: https://github.com/0x999-x/burpsuite-bambdas
  Source: GitHub
  Use Case: 
    Checks every request for parameters of type URL, if any are found and they are unique they will be saved to the path specified in the file variable, the generated file can later be used as a custom wordlist in an extension such as Param Miner
*/
var request = requestResponse.request();
// Parameter Type can be modified to your liking(URL,BODY,JSON,COOKIE,XML)
if (!request.hasParameters(HttpParameterType.URL)) {
    return false;
}

var parameters = request.parameters();
var uniqueParameters = new HashSet<String>();
var file = new File("/path/to/output.txt");
if (!file.exists()) {
    file.createNewFile();
}

var reader = new BufferedReader(new FileReader(file));
var writer = new BufferedWriter(new FileWriter(file, true));
while (reader.ready()) {
    uniqueParameters.add(reader.readLine());
}
reader.close();
for (var param : parameters) {
    // Parameter Type can be modified to your liking(URL,BODY,JSON,COOKIE,XML)
    if (param.type() == HttpParameterType.URL && !uniqueParameters.contains(param.name())) {
        writer.write(param.name());
        writer.newLine();
    }
}
writer.close();
return true;
```


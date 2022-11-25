/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package config

import (
    //"encoding/base64"
    "encoding/json"
    "flag"
    "github.com/drk1wi/Modlishka/log"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "bufio"
)

type Options struct {
    ProxyDomain          *string `json:"proxyDomain"`
    ListeningAddress     *string `json:"listeningAddress"`
    ListeningPortHTTP    *int    `json:"listeningPortHTTP"`
    ListeningPortHTTPS   *int    `json:"listeningPortHTTPS"`
    ProxyAddress         *string `json:"proxyAddress"`
    Target               *string `json:"target"`
    TargetRes            *string `json:"targetResources"`
    TargetRules          *string `json:"rules"`
    ForwardTo            *string `json:"forwardTo"`
    JsRules              *string `json:"jsRules"`
    BotList              *string `json:"botList"`
    BlockList            *string `json:"blockList"`
    TerminateTriggers    *string `json:"terminateTriggers"`
    TerminateRedirectUrl *string `json:"terminateRedirectUrl"`
    UnauthRedirectUrl    *string `json:"unauthRedirectUrl"`
    TrackingCookie       *string `json:"trackingCookie"`
    TrackingParam        *string `json:"trackingParam"`
    Debug                *bool   `json:"debug"`
    ForceHTTPS           *bool   `json:"forceHTTPS"`
    ForceHTTP            *bool   `json:"forceHTTP"`
    LogPostOnly          *bool   `json:"logPostOnly"`
    DisableSecurity      *bool   `json:"disableSecurity"`
    DynamicMode          *bool   `json:"dynamicMode"`
    LogRequestFile       *string `json:"log"`
    Plugins              *string `json:"plugins"`
    AllowSecureCookies   *bool   `json:"allowSecureCookies"`
    *TLSConfig
}

type TLSConfig struct {
    TLSCertificate *string `json:"cert"`
    TLSKey         *string `json:"certKey"`
    TLSPool        *string `json:"certPool"`
}

var (
    C = Options{
        ProxyDomain:      flag.String("proxyDomain", "", "Proxy domain name that will be used - e.g.: proxy.tld"),
        ListeningAddress: flag.String("listeningAddress", "127.0.0.1", "Listening address - e.g.: 0.0.0.0 "),
        ListeningPortHTTP: flag.Int("listeningPortHTTP", 80, "Listening port for HTTP requests"),
        ListeningPortHTTPS: flag.Int("listeningPortHTTPS", 443, "Listening port for HTTPS requests"),
        Target:           flag.String("target", "", "Target  domain name  - e.g.: target.tld"),
        TargetRes: flag.String("targetRes", "",
            "Comma separated list of domains that were not translated automatically. Use this to force domain translation - e.g.: static.target.tld"),
        TerminateTriggers: flag.String("terminateTriggers", "",
            "Session termination: Comma separated list of URLs from target's origin which will trigger session termination"),
        TerminateRedirectUrl: flag.String("terminateUrl", "",
            "URL to which a client will be redirected after Session Termination rules trigger"),
        UnauthRedirectUrl: flag.String("unauthUrl", "",
            "URL to which an unauthorized client will be redirected"),
        TargetRules: flag.String("rules", "",
            "Comma separated list of 'string' patterns and their replacements - e.g.: base64(new):base64(old),"+
                "base64(newer):base64(older)"),
        ForwardTo:  flag.String("forwardTo", "", "Legitimate resource/path on target server as landing page for client redirect"),
        JsRules: flag.String("jsRules", "", "Comma separated list of URL patterns and JS base64 encoded payloads that will be injected - e.g.: target.tld:base64(alert(1)),..,etc"),

        ProxyAddress: flag.String("proxyAddress", "", "Proxy that should be used (socks/https/http) - e.g.: http://127.0.0.1:8080 "),

        TrackingCookie: flag.String("trackingCookie", "id", "Name of the HTTP cookie used for track the client"),
        TrackingParam:  flag.String("trackingParam", "id", "Name of the HTTP parameter used to set up the HTTP cookie tracking of the client"),
        Debug:           flag.Bool("debug", false, "Print extra debug information"),
        DisableSecurity: flag.Bool("disableSecurity", false, "Disable proxy security features like anti-SSRF. 'Here be dragons' - disable at your own risk."),
        DynamicMode: flag.Bool("dynamicMode", false, "Enable dynamic mode for 'Client Domain Hooking'"),

        ForceHTTP:           flag.Bool("forceHTTP", false, "Strip all TLS from the traffic and proxy through HTTP only"),
        ForceHTTPS:           flag.Bool("forceHTTPS", false, "Strip all clear-text from the traffic and proxy through HTTPS only"),

        LogRequestFile: flag.String("log", "", "Local file to which fetched requests will be written (appended)"),

        LogPostOnly: flag.Bool("postOnly", false, "Log only HTTP POST requests"),

        BotList: flag.String("botList", "", "Path to robots/crawler file"),
        BlockList: flag.String("blockList", "", "Path to blacklisted IP CIDR file"),

        Plugins: flag.String("plugins", "all", "Comma separated list of enabled plugin names"),
        AllowSecureCookies: flag.Bool("allowSecureCookies", false, "Allow secure cookies to be set. Useful for when you are using HTTPS and cookies have SameSite=None"),
    }

    s = TLSConfig{
        TLSCertificate: flag.String("cert", "", "full or relative path to TLS certificate"),
        TLSKey:         flag.String("certKey", "", "full or relative path to TLS certificate key"),
        TLSPool:        flag.String("certPool", "", "full or relative path to Certification Authority certificate"),
    }

    JSONConfig = flag.String("config", "", "JSON configuration file. Convenient instead of using command line switches.")
)

func ReadTLS(tm string) string{
    tls := string("")
    if len(tm) > 0 {
        // Read file
        ct, err := os.OpenFile(tm, os.O_RDONLY, 0644)
        if err != nil {
            log.Fatalf("Failed to read Certificate file (%s)", tm)
        }
        defer ct.Close()

        fs := bufio.NewScanner(ct)
        fs.Split(bufio.ScanLines)
        for fs.Scan() {
            l := fs.Text()
            l = strings.Trim(l, " ") + string("\n")
            if len(l) > 1 {
                tls += l
            }
        }
        log.Infof("Loaded Certificate file %s", tm)
    }
    return tls
}

func ParseConfiguration() Options {

    flag.Parse()

    // Parse JSON for config
    if len(*JSONConfig) > 0 {
        for true {
            if !(strings.Contains(*JSONConfig, "/")) {
                *JSONConfig = string("./templates/") + *JSONConfig
            }
            if !(strings.Contains(filepath.Ext(*JSONConfig), "json")) {
                *JSONConfig = *JSONConfig + string(".json")
            }
            if (strings.Contains(*JSONConfig, "/templates/")) && (strings.Contains(*JSONConfig, ".json")){
                log.Infof("Config: Reading configuration file ~> ( %s )", *JSONConfig)
                break
            }
        }
        C.parseJSON(*JSONConfig)
    }

    // Process TLS configuration
    C.TLSConfig = &s

    // we can assume that if someone specified one of the following cmd line parameters then he should define all of them.
    if len(*s.TLSCertificate) > 0 || len(*s.TLSKey) > 0 || len(*s.TLSPool) > 0 {

        // Handle TLS Certificates
        if *C.ForceHTTP == false {
            if len(*C.TLSCertificate) > 0 {
                *C.TLSCertificate = ReadTLS(*C.TLSCertificate)
            }

            if len(*C.TLSKey) > 0 {
                *C.TLSKey = ReadTLS(*C.TLSKey)
            }

            if len(*C.TLSPool) > 0 {
                *C.TLSPool = ReadTLS(*C.TLSPool)
            }
        }

    }

    return C
}

func (c *Options) parseJSON(file string) {

    ct, err := os.Open(file)
    defer ct.Close()
    if err != nil {
        log.Fatalf("Error opening JSON configuration (%s): %s . Terminating.", file, err)
    }

    ctb, _ := ioutil.ReadAll(ct)
    err = json.Unmarshal(ctb, &c)
    if err != nil {
        log.Fatalf("Error unmarshalling JSON configuration (%s): %s . Terminating.", file, err)
    }

    err = json.Unmarshal(ctb, &s)
    if err != nil {
        log.Fatalf("Error unmarshalling JSON configuration (%s): %s . Terminating.", file, err)
    }

    C.TLSConfig = &s

}

func (c *Options) VerifyConfiguration() {

    if *c.ForceHTTP == true {
        if len(*c.ProxyDomain) == 0 || len(*c.ProxyDomain) == 0 {
            log.Warningf("Missing required parameters in oder start the proxy. Terminating.")
            log.Warningf("TIP: You will need to specify at least the following parameters to serve the page over HTTP: proxyDomain and target.")
            flag.PrintDefaults()
            os.Exit(1)
        }
    } else {    // default + HTTPS wrapper

            if len(*c.ProxyDomain) == 0 || len(*c.ProxyDomain) == 0 {
                log.Warningf("Missing required parameters in oder start the proxy. Terminating.")
                log.Warningf("TIP: You will need to specify at least the following parameters to serve the page over HTTP: proxyDomain and target.")
                flag.PrintDefaults()
                os.Exit(1)
            }


    }


    if *c.DynamicMode == true {
        log.Warningf("Dynamic Mode enabled: Proxy will accept and hook all incoming HTTP requests.")
    }


    if *c.ForceHTTP == true {
        log.Warningf("Force HTTP wrapper enabled: Proxy will strip all TLS traffic and handle requests over HTTP only")
    }

    if *c.ForceHTTPS == true {
        log.Warningf("Force HTTPS wrapper enabled: Proxy will strip all clear-text traffic and handle requests over HTTPS only")
    }

}

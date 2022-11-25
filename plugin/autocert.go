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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIIESTCCAzGgAwIBAgIUe5TKPxIcu1wgLPaFk9MEf4MYll4wDQYJKoZIhvcNAQEL
BQAwgbMxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhJbGxpbm9pczEQMA4GA1UEBwwH
Q2hpY2FnbzEVMBMGA1UECgwMTGV2YW50ZSBJbmMuMR0wGwYDVQQLDBRMZXZhbnRl
IFRlY2hub2xvZ2llczEeMBwGA1UEAwwVbG9vcGJhY2subW9kbGlzaGthLmlvMSkw
JwYJKoZIhvcNAQkBFhp0ZWNoQGxvb3BiYWNrLm1vZGxpc2hrYS5pbzAeFw0yMjA4
MTIxMTQwNTRaFw0yNTA2MDExMTQwNTRaMIGzMQswCQYDVQQGEwJVUzERMA8GA1UE
CAwISWxsaW5vaXMxEDAOBgNVBAcMB0NoaWNhZ28xFTATBgNVBAoMDExldmFudGUg
SW5jLjEdMBsGA1UECwwUTGV2YW50ZSBUZWNobm9sb2dpZXMxHjAcBgNVBAMMFWxv
b3BiYWNrLm1vZGxpc2hrYS5pbzEpMCcGCSqGSIb3DQEJARYadGVjaEBsb29wYmFj
ay5tb2RsaXNoa2EuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE
Nhb2R83jALuAV3C0Y+CIFLJsv2SD6gBDvgooXiXLhZrUz2aOnjU8cLMqNNnBLERM
khf8QCoLsdarG2/tKKewQc9uckqCMwaPEo9W8BtIIu8c/OjJmg675izxsPEzkzRj
BDnz/mmjl6Gnm9+I3GvtEBIB1ZVC9+sm32YC2ZVPnZc/MenOxQku2YxbrDg4dJus
ANupsGuCPIDPA9CDktRQT+17Yj9Bb7+u2r8lcm0n/YfVsmdQ8FMSoD0OIHYXinVP
0y80evyid3VpTZIGFSqUhUfChVm8zMreUWY6Z/h0zduv+TBS0N6xK8htC/psll2W
urinPeimkYqheskepRAHAgMBAAGjUzBRMB0GA1UdDgQWBBTvCNvSi+UTtmwEoiD4
44TZwzu4ITAfBgNVHSMEGDAWgBTvCNvSi+UTtmwEoiD444TZwzu4ITAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAFjF8YjpbNUoPTQbXW12ZLhW9v
lddifyTpB4aptNO68QVPYK1CdpvgF5rSa2pcIKF/mrgsxWocpWogLgWPcsJ5yPp4
7bQrPJESWYyJ2pvvQOznL0bjHvlBhGeek9YEOVAKQnpzdny2y+5GEPltFOqZN+Xd
78sEQxsEOwNhSnjf/XiwbwWj5kEDF2XvCKWmBI1soriTgoCrJ5z5e5uSR114kPkv
H3P7xcB2omC9FjCa0ycrcw8hnBPNGLCk1SzrmtDZtQt8T7uxi0VrB0U0+gPqjCLH
9ycmFsfUAcRiJbWkbOcG+kFeYakJ/R0hh4RLMIzYGnxWQKq6h+6ocQoxq8Az
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxDYW9kfN4wC7gFdwtGPgiBSybL9kg+oAQ74KKF4ly4Wa1M9m
jp41PHCzKjTZwSxETJIX/EAqC7HWqxtv7SinsEHPbnJKgjMGjxKPVvAbSCLvHPzo
yZoOu+Ys8bDxM5M0YwQ58/5po5ehp5vfiNxr7RASAdWVQvfrJt9mAtmVT52XPzHp
zsUJLtmMW6w4OHSbrADbqbBrgjyAzwPQg5LUUE/te2I/QW+/rtq/JXJtJ/2H1bJn
UPBTEqA9DiB2F4p1T9MvNHr8ond1aU2SBhUqlIVHwoVZvMzK3lFmOmf4dM3br/kw
UtDesSvIbQv6bJZdlrq4pz3oppGKoXrJHqUQBwIDAQABAoIBAHbBjjBN0W1dmh7Z
zZtBADsc28k6Jio5TSOzOA6qvRFrsgSv6xDS7MHCLI6VIl7q3gPCQMYqR8iAQL+b
gaj2/FeP3W6pujMHkyaxQxSJitmkWzkeUf8DQXu0mutF/xcKN6Deg/0LtQCQ3ATI
MQly79ex7FQz431+9FK4z9NVwitG1N5muwoAtiGjL0ADI6XLTd7ObUhRblI5SvDr
CLNNOHpCTdbz/41mG/8fqNAJcLjJX313NZsNUtqcLcQJ8MO51FmW0+ra34sXze2+
bUAAA4Xzpf73iGQQUU9aKLnAhn0lCcCSS6NW5WsGGDr2iAaNZyCFNORVVIxaTZjE
r2geKNECgYEA7k6eJfhkW/zdREvVCk5s5sqYsfBiBzQCvvoBkc7UzlNrGx5mwD9f
ZlEFbbSbKGToGpNJCmb1BDtmD9NGeAR3oPTx7DTBOPPGpQuTBgwM+JmkG368EXjL
VyOHjN8pByuiNcMS3hz3Z3mJfceJ4vAGS1O/NyUc5vWSV4y8cM41qfsCgYEA0sdg
zwYS0OINUGSACocmfmixAEJejFkE3dCU4TnIhNK0x0Eg4v7guSj9tPzPrIa2oVmM
+0PTpJm3C0s/DiJJuc607TqRLgRTOdaozhm5sXUb04HFv+xiEiLUH4YQ2Oe4Rcpv
hD5GWdBcqK+O9FTp7Klqm2Dj1LkFH+FXyqIbAGUCgYAwLv81CDMqkkce3wJVUiQc
ygvztnnroO2JNb2JgLtweFdopU37QxUD+A/T7beNhFGVxf/3tXeHAoeRXZObArQ5
fC1KKCSFYmzgxCVXDKq2vUH8OTTHh5f9p3Zp2llOVNk4a5fuBwdTCbTuFKFhnEx5
gJZiDQP6At8zCoazfE5HbwKBgDIxFBZ4RcbD7ZO1OuBG6p2zZGLBay5UjFodrzYq
wlsOqcnA8onbU7wDzNZqVTGqKpclcfLrZdyOVg40buF4vMGoPWE4TxX8Ja1iNnRN
n/BoCKZHAsX/DiNvc7/F9wEPvMuxtvhws+PzP/1TQOFhzwpyFVbGrbocDOJYkMVJ
8NAZAoGAVHdta9iIPP1FARJRL7l8LwQey8kqybOQDXf2jjGxef26tpSMY0QIJYmF
3m4SqpS6VTA2jE21ky+bxNk4LTcXGkKFBk3l8561VpxgffbGtWEOTlxCIBGzkRiM
qNHWrBSdNlBNACmr6wxkUaZF6Qv2rC/oc6Dcb0hAmMt1N3mk5kM=
-----END RSA PRIVATE KEY-----`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(1, 0, 0),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}

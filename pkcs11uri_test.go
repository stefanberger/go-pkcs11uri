/*
   (c) Copyright IBM Corporation, 2020

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package pkcs11uri

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var modulePaths = []string{
	"/usr/lib64/pkcs11/", // Fedora
	"/usr/lib/softhsm/",  // Ubuntu
}

func TestParse1(t *testing.T) {
	uri := New()

	original := "pkcs11:id=%02;object=SIGN%20pubkey;token=SSH%20key;manufacturer=piv_II?module-path=/usr/lib64/pkcs11/opensc-pkcs11.so"
	err := uri.Parse(original)

	if err != nil {
		t.Fatalf("Could not parse URI: %s", err)
	}

	for _, attr := range []string{"id", "object", "token", "manufacturer"} {
		if _, ok := uri.GetPathAttribute(attr, false); !ok {
			t.Fatalf("Path attribute %s is not available", attr)
		}
	}
	for _, attr := range []string{"module-path"} {
		if _, ok := uri.GetQueryAttribute(attr, false); !ok {
			t.Fatalf("Query attribute %s is not available", attr)
		}
	}

	_, err = uri.Format()
	if err != nil {
		t.Fatalf("Could not format the uri: %s", err)
	}
}

func verifyURI(t *testing.T, uri *Pkcs11URI, expecteduri string) {
	encoded, err := uri.Format()
	if err != nil {
		t.Fatalf("Could not format the uri: %s", err)
	}
	if encoded != expecteduri {
		t.Fatalf("Did not get expected URI '%s' but '%s'", expecteduri, encoded)
	}
}

func verifyPIN(t *testing.T, uri *Pkcs11URI, expectedpin string) {
	pin, err := uri.GetPIN()
	if err != nil {
		t.Fatalf("Could not get PIN: %s", err)
	}
	if pin != expectedpin {
		t.Fatalf("Did not get expected PIN value of '1234' but '%s'", pin)
	}
}

func TestConstruct1(t *testing.T) {
	uri := New()
	expecteduri := "pkcs11:id=%66%6F%6F"

	err := uri.AddPathAttribute("id", "%66oo")
	if err != nil {
		t.Fatalf("Could not add path attribute: %s", err)
	}

	verifyURI(t, uri, expecteduri)

	expectedpin := "1234"
	expecteduri += fmt.Sprintf("?pin-value=%s", expectedpin)

	err = uri.AddQueryAttribute("pin-value", expectedpin)
	if err != nil {
		t.Fatalf("Could not add query attribute: %s", err)
	}

	verifyURI(t, uri, expecteduri)
	verifyPIN(t, uri, expectedpin)
}

func writeTempfile(t *testing.T, value string) *os.File {
	tmpfile, err := ioutil.TempFile("", "mypin")
	if err != nil {
		t.Fatalf("Coult not create temporary file: %s", err)
	}
	if _, err := tmpfile.Write([]byte(value)); err != nil {
		t.Fatalf("Could not write to tempfile: %s", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Could not close tempfile: %s", err)
	}
	return tmpfile
}

func TestPinSource(t *testing.T) {
	uri := New()
	expectedpin := "4321"

	tmpfile := writeTempfile(t, expectedpin)
	defer os.Remove(tmpfile.Name())

	expecteduri := "pkcs11:id=%66%6F%6F?pin-source=file:" + tmpfile.Name()
	err := uri.AddPathAttribute("id", "foo")
	if err != nil {
		t.Fatalf("Could not add path attribute: %s", err)
	}
	err = uri.AddQueryAttribute("pin-source", "file:"+tmpfile.Name())
	if err != nil {
		t.Fatalf("Could not add query attribute: %s", err)
	}

	verifyURI(t, uri, expecteduri)
	verifyPIN(t, uri, expectedpin)

	expecteduri = "pkcs11:id=%66%6F%6F?pin-source=" + tmpfile.Name()

	uri.RemoveQueryAttribute("pin-source")
	err = uri.AddQueryAttribute("pin-source", tmpfile.Name())
	if err != nil {
		t.Fatalf("Could not add query attribute: %s", err)
	}

	verifyURI(t, uri, expecteduri)
	verifyPIN(t, uri, expectedpin)
}

func TestBadInput(t *testing.T) {
	uri := New()

	for _, entry := range [][]string{{"slot-id", "foo"}, {"library-version", "foo"}, {"library-version", "1.bar"}, {"type", "fobbar"}} {
		err := uri.AddPathAttribute(entry[0], entry[1])
		if err != nil {
			t.Fatalf("Could not add path attribute: %s", err)
		}

		if err := uri.Validate(); err == nil {
			t.Fatalf("uri validation should have failed due to malformed %s value '%s'", entry[0], entry[1])
		}
		uri.RemovePathAttribute(entry[0])
	}
}

func TestGoodInput(t *testing.T) {
	uri := New()

	for _, entry := range [][]string{{"slot-id", "1"}, {"library-version", "7"}, {"library-version", "1.8"}, {"type", "public"}} {
		err := uri.AddPathAttribute(entry[0], entry[1])
		if err != nil {
			t.Fatalf("Could not add path attribute: %s", err)
		}

		if err := uri.Validate(); err != nil {
			t.Fatalf("uri validation should have succeeded for %s value '%s': %s", entry[0], entry[1], err)
		}
		uri.RemovePathAttribute(entry[0])
	}
}

func TestURIs(t *testing.T) {
	uri := New()
	uris := []string{
		"pkcs11:",
		"pkcs11:object=my-pubkey;type=public",
		"pkcs11:object=my-key;type=private?pin-source=file:/etc/token",
		"pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;manufacturer=Snake%20Oil,%20Inc.;model=1.0;object=my-certificate;type=cert;id=%69%95%3E%5C%F4%BD%EC%91;serial=?pin-source=file:/etc/token_pin",
		"pkcs11:object=my-sign-key;type=private?module-name=mypkcs11",
		"pkcs11:object=my-sign-key;type=private?module-path=/mnt/libmypkcs11.so.1",
		"pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
		"pkcs11:slot-description=Sun%20Metaslot",
		"pkcs11:library-manufacturer=Snake%20Oil,%20Inc.;library-description=Soft%20Token%20Library;library-version=1.23",
		"pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",
		"pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;object=my-certificate;type=cert",
		"pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1;object=my-certificate;type=cert",
		"pkcs11:token=my-token;object=my-certificate;type=cert;vendor-aaa=value-a?pin-source=file:/etc/token_pin&vendor-bbb=value-b",
	}
	for _, uristring := range uris {
		err := uri.Parse(uristring)
		if err != nil {
			t.Fatalf("Could not parse URI '%s': %s", uristring, err)
		}

		encoded, err := uri.Format()
		if err != nil {
			t.Fatalf("Could not format URI '%s': %s", uristring, err)
		}
		// the order of attributes may be different but the string lengths are the same
		if len(encoded) != len(uristring) {
			t.Fatalf("String lengths are different: '%s' vs. '%s'", encoded, uristring)
		}
	}
}

func TestValidateEscapedAttrs(t *testing.T) {
	type data struct {
		uri    string
		testp  []string // pair of attribute and expected value in path part (unescaped, pct-encoded)
		testq  []string // pair of attribute and expected value in query part (unescaped, pct-encoded)
		format bool     // whether to format the URI and compare against given uri (equal strings)
	}
	input := []data{
		{
			uri:    "pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
			testp:  []string{"token", "Software PKCS#11 softtoken", "Software%20PKCS%2311%20softtoken"},
			format: false,
		}, {
			uri:    "pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",
			testp:  []string{"token", "My token% created by Joe", "My%20token%25%20created%20by%20Joe"},
			format: false,
		}, {
			// test pk11-query-res-avail and pk11-path-res-avail special characters
			uri:    "pkcs11:token=:[]@!$'()*+,=&?attr=:[]@!$'()*+,=/?",
			testp:  []string{"token", ":[]@!$'()*+,=&", ":[]@!$'()*+,=&"},
			testq:  []string{"attr", ":[]@!$'()*+,=/?", ":[]@!$'()*+,=/?"},
			format: true,
		}, {
			// test (some) unnecessarily escaped characters
			uri:    "pkcs11:token=%3a%5b%5d%40%21%24%27%28%29%2a%2b%2c%26%3d-%60%20%3c%3e%7b",
			testp:  []string{"token", ":[]@!$'()*+,&=-` <>{", ":[]@!$'()*+,&=-%60%20%3C%3E%7B"},
			format: false,
		}, {
			// test some non-printable characters that have to be escape;
			uri:    "pkcs11:token=%00%01%02Hello%FF%FE",
			testp:  []string{"token", "\x00\x01\x02Hello\xff\xfe", "%00%01%02Hello%FF%FE"},
			format: true,
		},
	}

	uri := New()
	for _, data := range input {
		err := uri.Parse(data.uri)
		if err != nil {
			t.Fatalf("Could not parse URI '%s': %s", data.uri, err)
		}
		if len(data.testp[1]) > 0 {
			v, _ := uri.GetPathAttribute(data.testp[0], false)
			if v != data.testp[1] {
				t.Fatalf("Got unexpected unescaped path attribute value '%s'; expected '%s'", v, data.testp[1])
			}
		}
		if len(data.testp[2]) > 0 {
			v, _ := uri.GetPathAttribute(data.testp[0], true)
			if v != data.testp[2] {
				t.Fatalf("Got unexpected pct-encoded path attribute value '%s'; expected '%s'", v, data.testp[2])
			}
		}
		if len(data.testq) > 0 {
			if len(data.testq[1]) > 0 {
				v, _ := uri.GetQueryAttribute(data.testq[0], false)
				if v != data.testq[1] {
					t.Fatalf("Got unexpected unescaped query attribute value '%s'; expected '%s'", v, data.testq[1])
				}
			}
			if len(data.testq[2]) > 0 {
				v, _ := uri.GetQueryAttribute(data.testq[0], true)
				if v != data.testq[2] {
					t.Fatalf("Got unexpected pct-encoded query attribute value '%s'; expected '%s'", v, data.testq[2])
				}
			}
		}
		if data.format {
			encoded, err := uri.Format()
			if err != nil {
				t.Fatalf("Could not format URI '%s': %s", data.uri, err)
			}
			if encoded != data.uri {
				t.Fatalf("Formatted URI is different than expected: '%s' vs. '%s'", encoded, data.uri)
			}
		}
	}
}

// This test requires SoftHSM to be installed, will warn otherwise
func TestGetModule(t *testing.T) {
	uri := New()
	uri.SetModuleDirectories(modulePaths)

	uristring := "pkcs11:?module-name=softhsm2"
	err := uri.Parse(uristring)
	if err != nil {
		t.Fatalf("Could not parse pkcs11 URI '%s': %s", uristring, err)
	}

	_, err = uri.GetModule()
	if err != nil {
		t.Skipf("Is softhsm2 not installed? GetModule() failed: %s", err)
	}
}

// This test requires SoftHSM to be installed, will warn otherwise
func TestGetModuleRestricted(t *testing.T) {
	uri := New()
	uri.SetModuleDirectories(modulePaths)

	uristring := "pkcs11:?module-name=softhsm2"
	err := uri.Parse(uristring)
	if err != nil {
		t.Fatalf("Could not parse pkcs11 URI '%s': %s", uristring, err)
	}

	// we don't want any results
	uri.SetAllowedModulePaths([]string{"/usr"})
	_, err = uri.GetModule()
	if err == nil {
		t.Errorf("GetModule() must fail due to allowed file paths: %s", err)
	}

	// this time we want module paths
	uri.SetAllowedModulePaths(modulePaths)
	_, err = uri.GetModule()
	if err != nil {
		t.Skipf("Is softhsm2 not installed? GetModule() failed: %s", err)
	}
}

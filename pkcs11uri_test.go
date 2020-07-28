package pkcs11uri

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
)

var modulePaths = []string{
	"/usr/lib64/pkcs11/", // Fedora
	"/usr/lib/softhsm/",  // Ubuntu
}

func TestParse1(t *testing.T) {
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
	}

	original := "pkcs11:id=%02;object=SIGN%20pubkey;token=SSH%20key;manufacturer=piv_II?module-path=/usr/lib64/pkcs11/opensc-pkcs11.so"
	err = uri.Parse(original)

	if err != nil {
		t.Fatalf("Could not parse URI: %s", err)
	}

	for _, attr := range []string{"id", "object", "token", "manufacturer"} {
		if _, ok := uri.GetPathAttribute(attr); !ok {
			t.Fatalf("Path attribute %s is not available", attr)
		}
	}
	for _, attr := range []string{"module-path"} {
		if _, ok := uri.GetQueryAttribute(attr); !ok {
			t.Fatalf("Query attribute %s is not available", attr)
		}
	}

	_, err = uri.Format()
	if err != nil {
		t.Fatalf("Could not format the uri: %s", err)
	}
}

func verifyURI(t *testing.T, uri Pkcs11URI, expecteduri string) {
	encoded, err := uri.Format()
	if err != nil {
		t.Fatalf("Could not format the uri: %s", err)
	}
	if encoded != expecteduri {
		t.Fatalf("Did not get expected URI '%s' but '%s'", expecteduri, encoded)
	}
}

func verifyPIN(t *testing.T, uri Pkcs11URI, expectedpin string) {
	pin, err := uri.GetPIN()
	if err != nil {
		t.Fatalf("Could not get PIN: %s", err)
	}
	if pin != expectedpin {
		t.Fatalf("Did not get expected PIN value of '1234' but '%s'", pin)
	}
}

func TestConstruct1(t *testing.T) {
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
	}
	expecteduri := "pkcs11:id=%66%6F%6F"
	uri.AddPathAttribute("id", "%66oo")
	verifyURI(t, uri, expecteduri)

	expectedpin := "1234"
	expecteduri += fmt.Sprintf("?pin-value=%s", expectedpin)
	uri.AddQueryAttribute("pin-value", expectedpin)

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
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}

	expectedpin := "4321"

	tmpfile := writeTempfile(t, expectedpin)
	defer os.Remove(tmpfile.Name())

	expecteduri := "pkcs11:id=%66%6F%6F?pin-source=file:" + tmpfile.Name()
	uri.AddPathAttribute("id", "foo")
	uri.AddQueryAttribute("pin-source", "file:"+tmpfile.Name())

	verifyURI(t, uri, expecteduri)
	verifyPIN(t, uri, expectedpin)

	expecteduri = "pkcs11:id=%66%6F%6F?pin-source=file:" + tmpfile.Name()
	uri.AddPathAttribute("id", "foo")
	uri.AddQueryAttribute("pin-source", tmpfile.Name())

	verifyURI(t, uri, expecteduri)
	verifyPIN(t, uri, expectedpin)
}

func TestBadInput(t *testing.T) {
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}

	for _, entry := range [][]string{{"slot-id", "foo"}, {"library-version", "foo"}, {"library-version", "1.bar"}, {"type", "fobbar"}} {
		uri.AddPathAttribute(entry[0], entry[1])
		if err := uri.Validate(); err == nil {
			t.Fatalf("uri validation should have failed due to malformed %s value '%s'", entry[0], entry[1])
		}
		uri.RemovePathAttribute(entry[0])
	}
}

func TestGoodInput(t *testing.T) {
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}

	for _, entry := range [][]string{{"slot-id", "1"}, {"library-version", "7"}, {"library-version", "1.8"}, {"type", "public"}} {
		uri.AddPathAttribute(entry[0], entry[1])
		if err := uri.Validate(); err != nil {
			t.Fatalf("uri validation should have succeeded for %s value '%s': %s", entry[0], entry[1], err)
		}
	}
}

func TestURIs(t *testing.T) {
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}
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
		err = uri.Parse(uristring)
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
	input := [][]string{
		{
			// pkcs11 URI
			"pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
			// attribute name and value to check
			"token", "Software PKCS#11 softtoken",
		}, {
			"pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",
			"token", "My token% created by Joe",
		},
	}

	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
	}
	for _, data := range input {
		err = uri.Parse(data[0])
		if err != nil {
			t.Fatalf("Could not parse URI '%s': %s", data[0], err)
		}
		v, _ := uri.GetPathAttribute(data[1])
		if v != data[2] {
			t.Fatalf("Got unexpected attribute value '%s'; expected '%s'", v, data[2])
		}
	}
}

// This test requires SoftHSM to be installed, will warn otherwise
func TestGetModule(t *testing.T) {
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}
	uri.SetModuleDirectories(modulePaths)

	uristring := "pkcs11:?module-name=softhsm2"
	err = uri.Parse(uristring)
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
	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}
	uri.SetModuleDirectories(modulePaths)

	uristring := "pkcs11:?module-name=softhsm2"
	err = uri.Parse(uristring)
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

func TestGetPINUsingCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("This test is only supported on Linux")
	}

	uri, err := New()
	if err != nil {
		t.Fatalf("Could not create a Pkcs11URI object")
		return
	}

	expectedpin := "1234"

	script := "#!/bin/sh\n"
	script += "echo -n " + expectedpin + "\n"
	tmpfile := writeTempfile(t, script)
	defer os.Remove(tmpfile.Name())

	err = os.Chmod(tmpfile.Name(), 0700)
	if err != nil {
		t.Fatalf("Could not change mode bits on file: %s", err)
	}

	uristring := "pkcs11:?pin-source=|" + tmpfile.Name()
	err = uri.Parse(uristring)
	if err != nil {
		t.Fatalf("Could not parse pkcs11 URI '%s': %s", uristring, err)
	}

	// this has to fail since we did not enable PIN commands
	_, err = uri.GetPIN()
	if err == nil {
		t.Fatalf("PIN command was not enabled and should have failed")
	}

	// this time it has to fail again since the tmpfile is not in the allowed list
	uri.SetEnableGetPINCommand(true, []string{tmpfile.Name() + "x"})
	_, err = uri.GetPIN()
	if err == nil {
		t.Fatalf("Getting the PIN from a command should have failed")
	}

	// this time it must work
	uri.SetEnableGetPINCommand(true, []string{tmpfile.Name()})
	pin, err := uri.GetPIN()
	if err != nil {
		t.Fatalf("Could not get PIN using command: %s", err)
	}
	if pin != expectedpin {
		t.Fatalf("Expected PIN '%s' but got '%s'", expectedpin, pin)
	}
}

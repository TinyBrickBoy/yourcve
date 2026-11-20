package ai

import "testing"

func TestValidate(t *testing.T) {
	ok := Summary{Category: "RCE", Summary: "A heap overflow in the resolver lets remote attackers run code."}
	if err := Validate("CVE-2024-1", &ok); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Summary{
		{Category: "RCE", Summary: "short"},
		{Category: "RCE", Summary: "Similar to CVE-2023-9999 this allows remote code execution in nginx."},
		{Category: "RCE", Summary: "This has a CVSS score of 9.8 and allows remote code execution."},
	} {
		if Validate("CVE-2024-1", &s) == nil {
			t.Errorf("accepted %q", s.Summary)
		}
	}
	odd := Summary{Category: "Banana", Summary: "Attackers can read arbitrary files from the server."}
	if Validate("CVE-2024-1", &odd) != nil || odd.Category != "Other" {
		t.Fatal(odd)
	}
}
